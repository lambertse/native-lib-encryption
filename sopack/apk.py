"""APK repackaging + self-signing.

Flow: for each requested lib/<abi>/*.so inside the APK, inject (encrypt + stub),
write it back STORED (uncompressed) so it stays page-mappable, strip the old
signature, then `zipalign -P 16` and `apksigner` with a generated keystore.

Re-signing changes the signing identity: the output is effectively a new app and
cannot be installed as an update over the original.
"""
from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .elf_inject import InjectResult, inject_so
from .stubs import SUPPORTED_ABIS

_LIB_RE = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")


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
    skipped: list[str] = field(default_factory=list)   # entry names not matched
    output: str = ""
    obf_seed: int | None = None   # per-pack O-MVLL seed when --obfuscate was used


def _is_target(entry: str, abi: str, so: str, wanted: set[str], abis: set[str]) -> bool:
    if abi not in abis:
        return False
    # Match by full lib path or by bare basename (which then applies to every ABI).
    return entry in wanted or so in wanted


def repackage(in_apk: str, out_apk: str, wanted_libs: list[str],
              cipher: str = "chacha20",
              abis: tuple[str, ...] = SUPPORTED_ABIS,
              keystore: KeystoreInfo | None = None,
              min_sdk: int | None = None,
              log: bool = False,
              obfuscate: bool = False,
              logger=print) -> RepackResult:
    wanted = set(wanted_libs)
    abis_set = set(abis)
    result = RepackResult(output=out_apk)

    with tempfile.TemporaryDirectory(prefix="sopack-") as tmp:
        unsigned = os.path.join(tmp, "unsigned.apk")
        aligned = os.path.join(tmp, "aligned.apk")

        # --obfuscate: build ONE fresh, seeded, O-MVLL-obfuscated stub set for this pack and
        # inject every lib with it (per-pack polymorphism — a different stub shape per app).
        stub_dir = None
        if obfuscate:
            from .obfuscate import build_obfuscated_stubs
            stub_dir = os.path.join(tmp, "obfstubs")
            os.makedirs(stub_dir, exist_ok=True)
            seed = build_obfuscated_stubs(stub_dir, seed=None, logger=logger)
            result.obf_seed = seed

        matched_any = False
        with zipfile.ZipFile(in_apk, "r") as zin, \
                zipfile.ZipFile(unsigned, "w") as zout:
            for item in zin.infolist():
                name = item.filename
                # Drop the previous signature — we re-sign.
                if name.startswith("META-INF/") and re.search(r"\.(RSA|DSA|EC|SF|MF)$|MANIFEST\.MF$", name):
                    continue
                data = zin.read(name)
                m = _LIB_RE.match(name)
                if m and _is_target(name, m.group(1), m.group(2), wanted, abis_set):
                    abi = m.group(1)
                    logger(f"  injecting {name} [{abi}] …")
                    src = os.path.join(tmp, "in.so")
                    dst = os.path.join(tmp, "out.so")
                    with open(src, "wb") as f:
                        f.write(data)
                    ir = inject_so(src, dst, abi, cipher=cipher, log=log,
                                   stub_dir=stub_dir)
                    with open(dst, "rb") as f:
                        data = f.read()
                    result.injected.append(ir)
                    matched_any = True
                    # STORED so the .so stays uncompressed & page-alignable.
                    zi = zipfile.ZipInfo(name, date_time=item.date_time)
                    zi.compress_type = zipfile.ZIP_STORED
                    zi.external_attr = item.external_attr
                    zout.writestr(zi, data)
                else:
                    if m:
                        result.skipped.append(name)
                    # Preserve original entry (compression and all).
                    zout.writestr(item, data)

        if not matched_any:
            raise RuntimeError(
                "no .so entries matched the requested list; nothing to encrypt. "
                f"requested={sorted(wanted)}"
            )

        # Align uncompressed entries to 16 KB pages (native `zipalign` if present and
        # runnable, else the built-in Python aligner — needed on hosts without an
        # arch-matching zipalign, e.g. aarch64).
        _align_apk(unsigned, aligned, logger=logger)

        # self-sign (v2/v3) with apksigner.
        ks = keystore or KeystoreInfo(path=os.path.join(
            os.path.expanduser("~"), ".sopack", "debug.keystore"))
        ensure_keystore(ks)
        sign_cmd = apksigner_cmd() + [
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
