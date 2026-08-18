"""APK repackaging + self-signing.

Flow: for each selected lib/<abi>/*.so inside the APK, inject (encrypt + stub),
write it back STORED (uncompressed) so it stays page-mappable, strip the old
signature, then `zipalign -P 16` and `apksigner` with a generated keystore.

Selection is either an explicit list (libraries.include) or, when that list is omitted,
every lib/<abi>/*.so in the input APK for the selected ABIs. Exclusion patterns always
win over selection; see ALWAYS_EXCLUDE_PATTERNS below.

Re-signing changes the signing identity: the output is effectively a new app and
cannot be installed as an update over the original.
"""
from __future__ import annotations

import fnmatch
import glob
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .elf_inject import InjectError, InjectResult, inject_so
from .stubs import DEFAULT_ABIS, SUPPORTED_ABIS

_LIB_RE = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")

# Excluded UNCONDITIONALLY: not overridable by naming one in libraries.include, and not
# removable by leaving them out of libraries.exclude. Patterns are fnmatch globs on the
# basename; a trailing ".so" is optional, so "libflutter" matches "libflutter.so".
#
# These two entries are here for DIFFERENT reasons - the old comment described only the
# first and was therefore untrue of the tuple it sat above:
#
#   libsopk_*        sopack's OWN injected artifacts - the shared provider
#                    (rt_meta.PROVIDER_SONAME) and the per-target thin helpers, emitted as
#                    libsopk_rt_<target>.so. Auto-selecting them on an already-packed APK
#                    would encrypt the very code that does the decrypting. This one is a
#                    correctness invariant of the tool, not a preference.
#   libvosWrapperEx  the V-Key/V-OS wrapper, which ships in the APKs this tool is used on
#                    and is already self-protected, so packing it buys nothing and risks
#                    interfering with its own integrity checks.
#
# Both are ALSO written into every generated config's `libraries.exclude` so a reader of the
# config can see them (config.LibraryConfig.exclude). That listing is for visibility only:
# this tuple is what makes deleting them there a no-op. build_excludes() de-duplicates, so
# appearing in both places costs nothing.
ALWAYS_EXCLUDE_PATTERNS = ("libsopk_*", "libvosWrapperEx")


# ---- external tool discovery ------------------------------------------------------
def _sdk_root() -> str | None:
    for var in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        v = os.environ.get(var)
        if v and os.path.isdir(v):
            return v
    return None


def find_tool(name: str) -> str:
    """Locate a build tool: PATH first, then the newest SDK build-tools dir."""
    p = shutil.which(name)
    if p:
        return p
    sdk = _sdk_root()
    if sdk:
        cands = sorted(glob.glob(os.path.join(sdk, "build-tools", "*", name)))
        if cands:
            return cands[-1]
    raise FileNotFoundError(
        f"could not find '{name}'. Put it on PATH or set ANDROID_SDK_ROOT to your SDK."
    )


def find_keytool() -> str:
    p = shutil.which("keytool")
    if p:
        return p
    jh = os.environ.get("JAVA_HOME")
    if jh:
        cand = os.path.join(jh, "bin", "keytool")
        if os.path.exists(cand):
            return cand
    raise FileNotFoundError("could not find 'keytool'. Install a JDK or set JAVA_HOME.")


def apksigner_cmd() -> list[str]:
    """Command prefix to run apksigner. Order: SOPACK_APKSIGNER_JAR (java -jar), the
    `apksigner` launcher on PATH / in the SDK, else apksigner.jar found under the SDK."""
    jar = os.environ.get("SOPACK_APKSIGNER_JAR")
    if jar:
        return [shutil.which("java") or "java", "-jar", jar]
    launcher = shutil.which("apksigner")
    if launcher:
        return [launcher]
    sdk = _sdk_root()
    if sdk:
        for pat in ("build-tools/*/apksigner", "build-tools/*/lib/apksigner.jar"):
            cands = sorted(glob.glob(os.path.join(sdk, pat)))
            if cands:
                if cands[-1].endswith(".jar"):
                    return [shutil.which("java") or "java", "-jar", cands[-1]]
                return [cands[-1]]
    raise FileNotFoundError(
        "could not find apksigner. Set SOPACK_APKSIGNER_JAR to apksigner.jar, or put "
        "apksigner on PATH, or set ANDROID_SDK_ROOT.")


# ---- keystore ---------------------------------------------------------------------
# Where a pack signs from when the caller names no keystore. A module constant rather than
# an inline literal because cli.py now builds a KeystoreInfo unconditionally (the config
# file always has keystore settings, even if they are all defaults) and both places have to
# mean the same file.
DEFAULT_KEYSTORE_PATH = os.path.join(os.path.expanduser("~"), ".sopack", "debug.keystore")


@dataclass
class KeystoreInfo:
    path: str
    alias: str = "sopack"
    store_pass: str = "sopack"
    key_pass: str = "sopack"


def ensure_keystore(ks: KeystoreInfo) -> KeystoreInfo:
    if os.path.exists(ks.path):
        return ks
    os.makedirs(os.path.dirname(os.path.abspath(ks.path)) or ".", exist_ok=True)
    subprocess.run([
        find_keytool(), "-genkeypair", "-v",
        "-keystore", ks.path, "-alias", ks.alias,
        "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
        "-storepass", ks.store_pass, "-keypass", ks.key_pass,
        "-dname", "CN=sopack, O=sopack, C=US",
    ], check=True)
    return ks


# ---- target selection -------------------------------------------------------------
@dataclass
class RepackResult:
    injected: list[InjectResult] = field(default_factory=list)
    # (entry, reason) for every lib/<abi>/*.so we deliberately did not select.
    untouched: list[tuple[str, str]] = field(default_factory=list)
    # (entry, InjectError message) for libraries that were selected but could not be
    # injected. Only ever populated in auto-select mode - an explicitly named library
    # still aborts the whole pack.
    failed: list[tuple[str, str]] = field(default_factory=list)
    output: str = ""
    # False when the output was left UNSIGNED - either signing.sign: false, or no apksigner on this
    # machine. An unsigned APK cannot be installed until something signs it, so the CLI has to
    # say so rather than letting a successful-looking pack imply an installable artifact.
    signed: bool = True


def build_excludes(exclude_libs=None) -> tuple[str, ...]:
    """Assemble the effective exclusion pattern list, most-authoritative first.

    ALWAYS_EXCLUDE_PATTERNS is prepended unconditionally, so a caller that passes an empty
    list - or one that dropped `libsopk_*` from its config - still cannot select sopack's
    own decryptor. De-duplicated because every generated config already lists those
    patterns: without this the CLI's "excluding:" line would name each of them twice, which
    reads as a bug.
    """
    return tuple(dict.fromkeys(list(ALWAYS_EXCLUDE_PATTERNS) + list(exclude_libs or ())))


def _match_lib_pattern(entry: str, so: str, pat: str) -> bool:
    """fnmatch on the basename with an optional .so suffix; full APK paths also match."""
    return (fnmatch.fnmatch(so, pat)
            or fnmatch.fnmatch(so, pat + ".so")
            or fnmatch.fnmatch(entry, pat))


def _classify(entry: str, abi: str, so: str, wanted: set[str] | None,
              abis: set[str], excludes: tuple[str, ...]) -> tuple[bool, str]:
    """(select?, reason-if-not). `wanted is None` means auto-select everything.

    Exclusion is checked before selection, so an excluded name is never packed even when
    it was named explicitly in libraries.include.
    """
    if abi not in abis:
        # Distinguish "you could widen `abis:` for this" from "sopack has no stub for it":
        # _LIB_RE matches any <abi> directory name, including lib/x86/ and lib/mips/ that
        # `abis:` would reject outright.
        return False, ("abi not selected" if abi in SUPPORTED_ABIS
                       else "abi not supported by sopack")
    for pat in excludes:
        if _match_lib_pattern(entry, so, pat):
            return False, f"excluded by {pat!r}"
    if wanted is None:
        return True, ""
    # Same matcher as the exclusion loop above, deliberately: a full APK path, a bare
    # basename (which then applies to every ABI), an optional trailing ".so", and fnmatch
    # globs all work in BOTH lists. This used to be exact set membership, so `include:
    # [libapp]` silently matched nothing and the pack aborted with "no .so entries matched"
    # while `exclude: [libflutter]` - written the same way, two lines below it in the same
    # config - worked fine. One matcher is the only way that stays true as the file is edited.
    if any(_match_lib_pattern(entry, so, pat) for pat in wanted):
        return True, ""
    return False, "not requested"


def repackage(in_apk: str, out_apk: str, wanted_libs: list[str] | None,
              # This is the LIBRARY default and is unreachable from the CLI, which always
              # passes cipher= explicitly from the config. sopack/config.py owns the
              # user-facing default (wbaes). Do not "align" the two: flipping this to wbaes
              # fires the find_wb_keygen preflight below in every test that calls repackage
              # without a cipher, on machines that have no white-box build.
              cipher: str = "chacha20",
              abis: tuple[str, ...] = DEFAULT_ABIS,
              keystore: KeystoreInfo | None = None,
              min_sdk: int | None = None,
              log: bool = False,
              wb_keygen: str | None = None,
              allow_helper_log: bool = False,
              exclude_libs: list[str] | None = None,
              no_sign: bool = False,
              logger=print) -> RepackResult:
    # `None` means auto-select every lib/<abi>/*.so; an empty list is NOT the same thing
    # (config.py rejects `libraries.include: []` rather than silently widening the scope).
    auto = wanted_libs is None
    wanted = None if auto else set(wanted_libs)
    excludes = build_excludes(exclude_libs)
    abis_set = set(abis)
    result = RepackResult(output=out_apk)

    # wbaes preflight: resolve a RUNNABLE host wb_keygen now, so a wrong tool fails before we
    # start injecting (not mid-pack). Also surfaces the Android-vs-host mistake up front.
    if cipher == "wbaes":
        from .provision import find_wb_keygen
        wb_keygen = find_wb_keygen(wb_keygen)   # raises with guidance if unusable
        logger(f"  using host wb_keygen: {wb_keygen}")

    with tempfile.TemporaryDirectory(prefix="sopack-") as tmp:
        unsigned = os.path.join(tmp, "unsigned.apk")
        aligned = os.path.join(tmp, "aligned.apk")

        matched_any = False
        candidates = 0                        # lib/<abi>/*.so entries seen, any ABI
        seen_names: set[str] = set()          # every entry written (collision guard)
        # wbaes: (lib/<abi>/name, bytes, target's ZIP date_time)
        extra_helpers: list[tuple[str, bytes, tuple[int, int, int, int, int, int]]] = []
        # wbaes: ONE long-term key and ONE shared provider per ABI. Sealed lazily on that
        # ABI's first target, then reused for every later target in it - which is what lets a
        # single ~455 KB blob replace N of them.
        pack_keys: dict[str, object] = {}
        # abi -> ZIP date_time to stamp that ABI's provider with (see the helper note below).
        provider_dates: dict[str, tuple[int, int, int, int, int, int]] = {}
        # abi -> thin helper sonames staged, for the pack-level closure assertion afterwards.
        thin_by_abi: dict[str, list[str]] = {}
        with zipfile.ZipFile(in_apk, "r") as zin, \
                zipfile.ZipFile(unsigned, "w") as zout:
            for item in zin.infolist():
                name = item.filename
                # Drop the previous signature - we re-sign.
                if name.startswith("META-INF/") and re.search(r"\.(RSA|DSA|EC|SF|MF)$|MANIFEST\.MF$", name):
                    continue
                data = zin.read(name)
                m = _LIB_RE.match(name)
                select, why = (False, "")
                if m:
                    candidates += 1
                    select, why = _classify(name, m.group(1), m.group(2),
                                            wanted, abis_set, excludes)
                if select:
                    abi = m.group(1)
                    logger(f"  injecting {name} [{abi}] …")
                    src = os.path.join(tmp, "in.so")
                    dst = os.path.join(tmp, "out.so")
                    with open(src, "wb") as f:
                        f.write(data)
                    if cipher == "wbaes" and abi not in pack_keys:
                        # Sealed lazily, on this ABI's first target. That means a stale
                        # pre-3.0.0 wb_keygen fails mid-loop rather than up front - which is
                        # safe here only because every intermediate lives in `tmp` and
                        # `out_apk` is not written until signing, so a raise leaves no partial
                        # output. Do not move the output into the loop without hoisting this.
                        from .provision import provision_pack
                        logger(f"  sealing the shared white-box key for {abi} …")
                        pack_keys[abi] = provision_pack(wb_keygen=wb_keygen)
                    try:
                        ir = inject_so(src, dst, abi, cipher=cipher, log=log,
                                       wb_keygen=wb_keygen, target_name=m.group(2),
                                       allow_helper_log=allow_helper_log,
                                       pack_key=pack_keys.get(abi))
                    except InjectError as e:
                        # An explicitly named library still aborts the pack - the user
                        # asked for THAT library and a silent downgrade to cleartext would
                        # be a lie. Under auto-select the list contains libraries the user
                        # never individually considered (prebuilts with no .text, no
                        # .dynamic slack, 4 KB-aligned arm64 …), so one of them must not
                        # kill the run; it is skipped and reported instead.
                        if not auto:
                            # inject_so reports the temp copy's path, not the APK entry -
                            # fine when one library was named, useless once selection is
                            # implicit. Prefix the entry either way.
                            raise InjectError(f"{name}: {e}") from e
                        logger(f"  warning: skipping {name}: {e}")
                        result.failed.append((name, str(e)))
                        # `data` is still the pristine zin.read(name) here - it is only
                        # reassigned below, after a successful inject. A raise also stages
                        # nothing: extra_helpers/thin_by_abi are fed from `ir`, which does
                        # not exist on this path.
                        zout.writestr(item, data)
                        seen_names.add(name)
                        continue
                    with open(dst, "rb") as f:
                        data = f.read()
                    result.injected.append(ir)
                    matched_any = True
                    # wbaes: stage the per-target helper .so to add into lib/<abi>/.
                    # Carry the target's own timestamp: a default ZipInfo date_time is
                    # 1980-01-01, which stands out against the Gradle-built entries around it
                    # and marks the helpers as post-processed artifacts. That mismatch was the
                    # first thing a static-analysis report noticed about a shipped APK,
                    # before any disassembly.
                    if ir.helper_path and ir.helper_soname:
                        hname = f"lib/{abi}/{ir.helper_soname}"
                        with open(ir.helper_path, "rb") as hf:
                            extra_helpers.append((hname, hf.read(), item.date_time))
                        thin_by_abi.setdefault(abi, []).append(ir.helper_soname)
                        provider_dates.setdefault(abi, item.date_time)
                    # STORED so the .so stays uncompressed & page-alignable.
                    zi = zipfile.ZipInfo(name, date_time=item.date_time)
                    zi.compress_type = zipfile.ZIP_STORED
                    zi.external_attr = item.external_attr
                    zout.writestr(zi, data)
                    seen_names.add(name)
                else:
                    if m:
                        result.untouched.append((name, why))
                    # Preserve original entry (compression and all).
                    zout.writestr(item, data)
                    seen_names.add(name)

            # Emit ONE shared white-box provider per ABI, after the loop - it carries that
            # ABI's single sealed blob, so it cannot be produced per target.
            from .elf_inject import emit_provider
            from .rt_meta import PROVIDER_SONAME
            # Keyed on thin_by_abi, NOT pack_keys: the key is sealed lazily *before*
            # inject_so, so an ABI whose every target was skipped (auto-select fail-soft
            # above) has a pack_keys entry but no thin helper. Emitting its provider would
            # add ~936 KB of white-box to the APK with nothing depending on it.
            for abi in thin_by_abi:
                pk = pack_keys[abi]
                pname = f"lib/{abi}/{PROVIDER_SONAME}"
                ppath = os.path.join(tmp, f"provider-{abi}.so")
                logger(f"  emitting shared white-box provider for {abi} …")
                emit_provider(abi, pk, ppath, allow_helper_log=allow_helper_log)
                with open(ppath, "rb") as pf:
                    extra_helpers.append(
                        (pname, pf.read(), provider_dates.get(abi, (1980, 1, 1, 0, 0, 0))))

            # Add the wbaes helpers and providers as NEW STORED entries (the packer's only
            # add-file path).
            #
            # A collision is handled differently for the two kinds. For a per-target helper it is
            # benign - the soname is derived from the target and prefixed libsopk_rt_, so a clash
            # means the APK already had one and skipping keeps the existing bytes. For the
            # PROVIDER it is fatal: silently skipping it would leave every thin helper resolving
            # against a pre-existing libsopk_wb.so carrying a FOREIGN blob, so no session key
            # would unwrap and every target would abort on device.
            provider_names = {f"lib/{abi}/{PROVIDER_SONAME}" for abi in thin_by_abi}
            for hname, hdata, hdate in extra_helpers:
                if hname in seen_names:
                    if hname in provider_names:
                        raise RuntimeError(
                            f"{hname} already exists in this APK. It cannot be reused: it would "
                            "carry a different sealed blob than the one the thin helpers were "
                            "wrapped against, so every packed library would fail to decrypt. "
                            "Pack an APK that has not already been packed.")
                    logger(f"  warning: helper {hname} already present; not overwriting")
                    continue
                logger(f"  adding {hname} …")
                zi = zipfile.ZipInfo(hname, date_time=hdate)
                zi.compress_type = zipfile.ZIP_STORED
                zi.external_attr = (0o644 << 16)
                zout.writestr(zi, hdata)
                seen_names.add(hname)

            # Pack-level closure. `_self_verify_wbaes` runs per target and structurally cannot
            # see this: every thin helper depends on lib/<abi>/libsopk_wb.so, so if that entry is
            # missing the app fails 100% of the time, inside whatever dlopen'd the target.
            for abi, thin in thin_by_abi.items():
                pname = f"lib/{abi}/{PROVIDER_SONAME}"
                if pname not in seen_names:
                    raise RuntimeError(
                        f"{len(thin)} thin helper(s) for {abi} were staged but {pname} was not - "
                        f"every one of them DT_NEEDEDs it, so the app would fail to load. This "
                        f"is a packer bug, not a bad input.")

        if not matched_any:
            if not auto:
                raise RuntimeError(
                    "no .so entries matched the requested list; nothing to encrypt. "
                    f"requested={sorted(wanted)}")
            if candidates == 0:
                raise RuntimeError(
                    "this APK has no lib/<abi>/*.so entries at all; nothing to encrypt.")
            raise RuntimeError(
                f"none of the {candidates} lib/<abi>/*.so entries in this APK were packed: "
                f"{len(result.untouched)} excluded or outside `abis:` "
                f"{','.join(sorted(abis_set))}, {len(result.failed)} could not be injected. "
                "See the per-library reasons above.")

        # Align uncompressed entries to 16 KB pages (native `zipalign` if present and
        # runnable, else the built-in Python aligner - needed on hosts without an
        # arch-matching zipalign, e.g. aarch64).
        _align_apk(unsigned, aligned, logger=logger)

        # self-sign (v2/v3) with apksigner.
        #
        # Resolve apksigner BEFORE touching the keystore. ensure_keystore shells out to keytool
        # and writes ~/.sopack/debug.keystore, so probing in the other order generates a 2048-bit
        # key pair and only then discovers there is nothing to sign with - which is what used to
        # happen, and it left a keystore behind on a machine that cannot sign at all.
        signer: list[str] | None = None
        if no_sign:
            logger("  skipping signing (signing.sign: false)")
        else:
            try:
                signer = apksigner_cmd()
            except FileNotFoundError as e:
                # Best-effort by design: the packing work is done and the aligned APK is a
                # legitimate artifact for a pipeline that signs with its own production key
                # later. Refusing here would throw that away over a missing tool.
                logger(f"  WARNING: {e}")
                logger("  WARNING: leaving the output UNSIGNED. It cannot be installed as-is - "
                       "sign it before `adb install`, or set `signing.sign: false` to make this "
                       "explicit.")

        if signer is None:
            result.signed = False
            shutil.copyfile(aligned, out_apk)
        else:
            ks = keystore or KeystoreInfo(path=DEFAULT_KEYSTORE_PATH)
            ensure_keystore(ks)
            sign_cmd = signer + [
                "sign",
                "--ks", ks.path, "--ks-key-alias", ks.alias,
                "--ks-pass", f"pass:{ks.store_pass}", "--key-pass", f"pass:{ks.key_pass}",
            ]
            if min_sdk is not None:
                sign_cmd += ["--min-sdk-version", str(min_sdk)]
            sign_cmd += ["--out", out_apk, aligned]
            subprocess.run(sign_cmd, check=True)

    return result


# ---- 16 KB alignment --------------------------------------------------------------
def _align_apk(src: str, dst: str, page: int = 16384, logger=print) -> None:
    zipalign = shutil.which("zipalign")
    if not zipalign:
        sdk = _sdk_root()
        if sdk:
            c = sorted(glob.glob(os.path.join(sdk, "build-tools", "*", "zipalign")))
            zipalign = c[-1] if c else None
    if zipalign:
        try:
            subprocess.run([zipalign, "-P", str(page // 1024), "-f", "4", src, dst],
                           check=True, capture_output=True)
            return
        except (subprocess.CalledProcessError, OSError) as e:
            logger(f"  (native zipalign unusable: {e}; using built-in aligner)")
    python_zipalign(src, dst, page)


def python_zipalign(src: str, dst: str, page: int = 16384) -> None:
    """Rewrite a zip so every STORED entry's data begins on an aligned offset (16 KB
    for .so, 4 bytes otherwise) by padding the local-header extra field. Compressed
    entries are copied unchanged. Mirrors what `zipalign -P` does before apksigner."""
    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.compress_type == zipfile.ZIP_STORED:
                align = page if item.filename.endswith(".so") else 4
                # local header = 30 + name + extra; pad extra so data offset % align == 0
                base = zout.fp.tell() + 30 + len(item.filename.encode("utf-8"))
                pad = (-(base + len(item.extra))) % align
                if pad:
                    item.extra = (item.extra or b"") + b"\x00" * pad
            zout.writestr(item, data)


def verify_signature(apk: str, min_sdk: int | None = None) -> str:
    cmd = apksigner_cmd() + ["verify", "--print-certs"]
    if min_sdk is not None:
        cmd += ["--min-sdk-version", str(min_sdk)]
    cmd.append(apk)
    out = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return out.stdout
