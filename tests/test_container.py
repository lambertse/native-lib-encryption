"""APK-vs-AAB detection, and packing a bundle through the same code path.

The two things most worth pinning here are NOT the happy path:

  * an APK's nested `assets/lib/<abi>/x.so` must stay invisible to selection. The tempting way to
    support bundles was one regex with an optional module prefix, which would have started
    encrypting entries that sopack has ignored in every APK ever packed - a silent widening with no
    error to notice.
  * a bundle's added artifacts must land in the SAME module directory as their target, and the
    shared white-box provider must be one per (module, abi) carrying one blob per ABI. Get either
    half wrong and the failure is on-device only: a thin helper whose DT_NEEDED cannot resolve, or
    one that unwraps against another module's blob.
"""
from __future__ import annotations

import json
import os
import zipfile

import pytest

from conftest import mkaab, mkapk
from sopack import apk, cli, container, diag
from sopack.elf_inject import InjectResult
from sopack.errors import InputError
from sopack.rt_meta import PROVIDER_SONAME


# ---- 1. detection is by content, not extension -------------------------------------------
def test_detects_an_apk_by_its_root_manifest(tmp_path):
    assert container.detect(mkapk(tmp_path / "in.apk")) is container.APK


def test_detects_a_bundle_by_its_root_bundleconfig(tmp_path):
    assert container.detect(mkaab(tmp_path / "in.aab")) is container.AAB


def test_extension_is_not_consulted(tmp_path):
    """A bundle named .apk is still a bundle. The name is a convention; the contents are a fact,
    and misclassifying costs a full rewrite of the input before anything fails."""
    assert container.detect(mkaab(tmp_path / "misnamed.apk")) is container.AAB
    assert container.detect(mkapk(tmp_path / "misnamed.aab")) is container.APK


def test_a_zip_that_is_neither_is_an_input_error(tmp_path):
    p = tmp_path / "plain.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("hello.txt", b"hi")
    with pytest.raises(InputError, match="neither an APK nor an Android App Bundle"):
        container.detect(str(p))


def test_not_a_zip_stays_a_badzipfile(tmp_path):
    """Left to propagate on purpose: cli maps it to the same exit code, and "not a zip" is a
    different diagnosis than "a zip of the wrong kind"."""
    p = tmp_path / "nope.apk"
    p.write_bytes(b"not a zip at all")
    with pytest.raises(zipfile.BadZipFile):
        container.detect(str(p))


@pytest.mark.parametrize("entry,expected", [
    ("lib/arm64-v8a/libfoo.so", "arm64-v8a"),
    ("base/lib/arm64-v8a/libfoo.so", "arm64-v8a"),
    ("feature1/lib/x86_64/libfoo.so", "x86_64"),
    ("classes.dex", "?"),
])
def test_abi_of_handles_both_shapes(entry, expected):
    """One implementation for the whole tool. The two copies this replaced did
    `entry.split("/")[1]`, which reports a bundle's ABI as the literal "lib" - so a packed
    bundle's per-ABI summary and report.json's per_abi both counted under an ABI named "lib"."""
    assert container.abi_of(entry) == expected


# ---- 2. the entry patterns do not bleed into one another ----------------------------------
def test_an_apks_nested_library_is_not_even_a_candidate(tmp_path):
    """The regression a merged optional-prefix regex would have introduced.

    `assets/lib/arm64-v8a/*.so` is data an app unpacks itself, not a library bionic loads, and it
    has never been selectable. It must not become selectable because bundles need a module segment.
    """
    src = mkapk(tmp_path / "in.apk", ["assets/lib/arm64-v8a/nested.so",
                                      "extras/lib/arm64-v8a/nested.so"])
    with pytest.raises(RuntimeError, match="no lib/<abi>/\\*\\.so entries at all"):
        apk.repackage(src, str(tmp_path / "out.apk"), None, logger=lambda *_: None)


def test_a_bundle_requires_the_module_segment(tmp_path):
    """The mirror image: `lib/<abi>/x.so` at a bundle's root is not where bundletool puts
    libraries, so it is not a target either. Requiring the segment is what keeps the two patterns
    from being one loose one."""
    src = mkaab(tmp_path / "in.aab")
    with zipfile.ZipFile(src, "a") as z:
        z.writestr("lib/arm64-v8a/libstray.so", b"\x7fELF-not-really")
    with pytest.raises(RuntimeError, match="no <module>/lib/<abi>/\\*\\.so entries at all"):
        apk.repackage(src, str(tmp_path / "out.aab"), None, logger=lambda *_: None)


def test_error_wording_names_the_container_it_saw(tmp_path):
    src = mkaab(tmp_path / "in.aab", [
        "base/lib/arm64-v8a/libflutter.so",     # excluded by the caller's list
        "base/lib/x86_64/libapp.so",            # outside the default abis
    ])
    with pytest.raises(RuntimeError, match=r"none of the 2 <module>/lib/<abi>/\*\.so entries in "
                                           r"this AAB were packed"):
        apk.repackage(src, str(tmp_path / "out.aab"), None,
                      exclude_libs=["libflutter"], logger=lambda *_: None)


# ---- 3. selection patterns keep working across the two shapes ----------------------------
@pytest.mark.parametrize("pat", [
    "libapp",                        # bare basename
    "libapp.so",                     # with the suffix
    "lib*.so",                       # a glob
    "lib/arm64-v8a/libapp.so",       # the path as every doc and config writes it
    "base/lib/arm64-v8a/libapp.so",  # the literal bundle entry
])
def test_a_bundle_entry_matches_paths_written_either_way(pat):
    """`include:`/`exclude:` entries are written by hand, and nobody writes the module prefix.
    Silently not matching an EXCLUDE is the dangerous half: that is how sopack's own decryptor
    would get fed back through the injector on a re-pack."""
    assert apk._match_lib_pattern("base/lib/arm64-v8a/libapp.so", "libapp.so", pat)


def test_a_module_named_mylib_is_not_sliced_mid_name():
    """The module-relative form is cut at "/lib/", not at "lib/" - otherwise a module called
    "mylib" yields "lib/lib/arm64-v8a/..." and matches nothing."""
    assert apk._match_lib_pattern("mylib/lib/arm64-v8a/libapp.so", "libapp.so",
                                  "lib/arm64-v8a/libapp.so")


# ---- 4. packing a bundle: where things land, and what stays compressed -------------------
def _fake_wbaes(monkeypatch, *, sealed):
    """Run the wbaes bookkeeping without a white-box toolchain.

    `repackage` imports provision/elf_inject lazily inside the function body, so patching the
    modules is enough. `sealed` collects one entry per seal, which is how the test can assert that
    a two-module bundle seals ONE key per ABI rather than one per module.
    """
    from sopack import elf_inject, provision

    monkeypatch.setattr(provision, "find_wb_keygen", lambda *_a, **_k: "/fake/wb_keygen")

    class _PackKey:
        def __init__(self, n):
            self.n = n

    def _provision_pack(**kw):
        sealed.append(kw)
        return _PackKey(len(sealed))

    monkeypatch.setattr(provision, "provision_pack", _provision_pack)

    def _emit_provider(abi, pack, out_path, **kw):
        # The provider's bytes identify which sealed key it carries, so a test can prove that
        # every copy for an ABI carries the SAME one.
        with open(out_path, "wb") as f:
            f.write(b"PROVIDER-%s-key%d" % (abi.encode(), pack.n))

    monkeypatch.setattr(elf_inject, "emit_provider", _emit_provider)

    def _inject(src, dst, abi, *, target_name=None, cipher="chacha20", **kw):
        with open(dst, "wb") as f:
            f.write(b"INJECTED")
        soname = f"libsopk_rt_{target_name[:-3]}.so"
        helper = os.path.join(os.path.dirname(dst), soname)
        with open(helper, "wb") as f:
            f.write(b"THIN-HELPER")
        return InjectResult(abi=abi, text_rva=0x1000, text_size=8, seg_rva=0x2000,
                            entry_rva=0x2010, strategy="DT_NEEDED-wbaes", cipher=cipher,
                            helper_path=helper, helper_soname=soname)

    monkeypatch.setattr(apk, "inject_so", _inject)


def test_bundle_helpers_land_beside_their_target(tmp_path, monkeypatch):
    sealed: list = []
    _fake_wbaes(monkeypatch, sealed=sealed)
    src = mkaab(tmp_path / "in.aab", ["base/lib/arm64-v8a/libapp.so",
                                      "base/lib/arm64-v8a/libpki.so"])
    out = str(tmp_path / "out.aab")
    res = apk.repackage(src, out, None, cipher="wbaes", logger=lambda *_: None)

    with zipfile.ZipFile(out) as z:
        names = z.namelist()
    assert "base/lib/arm64-v8a/libsopk_rt_libapp.so" in names
    assert "base/lib/arm64-v8a/libsopk_rt_libpki.so" in names
    assert f"base/lib/arm64-v8a/{PROVIDER_SONAME}" in names
    # Nothing at the zip root: an entry written to `lib/<abi>/` would be outside every module and
    # would never reach a generated APK, so the app would fail to resolve the DT_NEEDED.
    assert not [n for n in names if n.startswith("lib/")]
    assert len(res.injected) == 2
    assert len(sealed) == 1, "one KEK per ABI, not one per target"


def test_two_modules_get_a_provider_each_carrying_one_key_per_abi(tmp_path, monkeypatch):
    """Each module becomes its own split APK, so each needs its own copy of the provider - but
    bionic resolves a DT_NEEDED soname once per process, so both copies must carry the SAME sealed
    blob. Sealing per module would put two KEKs behind one soname and a helper from one module
    would unwrap against the other's blob, aborting on device."""
    sealed: list = []
    _fake_wbaes(monkeypatch, sealed=sealed)
    src = mkaab(tmp_path / "in.aab", ["base/lib/arm64-v8a/libapp.so",
                                      "feature1/lib/arm64-v8a/libfeat.so"])
    out = str(tmp_path / "out.aab")
    apk.repackage(src, out, None, cipher="wbaes", logger=lambda *_: None)

    with zipfile.ZipFile(out) as z:
        base = z.read(f"base/lib/arm64-v8a/{PROVIDER_SONAME}")
        feat = z.read(f"feature1/lib/arm64-v8a/{PROVIDER_SONAME}")
        assert "feature1/lib/arm64-v8a/libsopk_rt_libfeat.so" in z.namelist()
    assert len(sealed) == 1, "one KEK for the whole ABI, across every module"
    assert base == feat, "both providers must carry the same sealed blob"


def _have_wbaes_toolchain() -> bool:
    """A real wbaes pack needs a host wb_keygen AND this ABI's built skeletons - neither is
    committed, so the real-injection test below skips rather than fails on a fresh checkout."""
    from sopack import stubs
    from sopack.provision import find_wb_keygen
    from sopack.stubs import StubMissingError
    try:
        find_wb_keygen(None)
        stubs.helper_skeleton_path("arm64-v8a")
        stubs.provider_skeleton_path("arm64-v8a")
        return True
    except (FileNotFoundError, StubMissingError):
        # Narrow on purpose. This is the ONLY test asserting that two real `emit_provider` calls
        # agree byte-for-byte, so a bare `except Exception` would turn any future signature change
        # in the probed helpers into a permanent silent skip instead of a failure.
        return False


@pytest.mark.skipif(not _have_wbaes_toolchain(),
                    reason="needs a host wb_keygen + built arm64-v8a wbaes skeletons")
def test_two_modules_share_one_real_sealed_blob(tmp_path):
    """The same invariant as the faked test above, but through the REAL `provision_pack` and
    `emit_provider` on a real `.so`.

    Worth having both: the fake proves the bookkeeping (one seal, two slots), and this proves the
    thing that actually ships - that two independently emitted providers are byte-identical, so
    whichever copy bionic resolves for the shared soname unwraps every module's helpers.
    """
    so = open(os.path.join(os.path.dirname(__file__), "fixtures", "mini_arm64.so"), "rb").read()
    src = tmp_path / "in.aab"
    with zipfile.ZipFile(src, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("BundleConfig.pb", b"\x0a\x08\x12\x061.18.1")
        for mod in ("base", "feature1"):
            z.writestr(f"{mod}/manifest/AndroidManifest.xml", b"\x0a\x08proto")
        z.writestr("base/lib/arm64-v8a/libmini.so", so)
        z.writestr("feature1/lib/arm64-v8a/libmini2.so", so)

    out = str(tmp_path / "out.aab")
    res = apk.repackage(str(src), out, None, cipher="wbaes", logger=lambda *_: None)
    assert len(res.injected) == 2

    with zipfile.ZipFile(out) as z:
        base = z.read(f"base/lib/arm64-v8a/{PROVIDER_SONAME}")
        feat = z.read(f"feature1/lib/arm64-v8a/{PROVIDER_SONAME}")
    assert base == feat, "two providers for one ABI must carry the same sealed blob"


def test_a_bundle_keeps_its_entry_compression_and_an_apk_does_not(tmp_path, monkeypatch):
    """An APK's library is STORED so it can be mapped straight out of the zip. A bundle's cannot
    be mapped from the bundle at all - bundletool re-packs it into the APKs it generates - so
    STORED there would only inflate the artifact (~100 MB of libraries, in a real one)."""
    _fake_wbaes(monkeypatch, sealed=[])

    aab = mkaab(tmp_path / "in.aab", ["base/lib/arm64-v8a/libapp.so"])
    aab_out = str(tmp_path / "out.aab")
    apk.repackage(aab, aab_out, None, cipher="wbaes", logger=lambda *_: None)
    with zipfile.ZipFile(aab_out) as z:
        assert z.getinfo("base/lib/arm64-v8a/libapp.so").compress_type == zipfile.ZIP_DEFLATED
        assert z.getinfo("base/dex/classes.dex").compress_type == zipfile.ZIP_DEFLATED

    src = mkapk(tmp_path / "in.apk", ["lib/arm64-v8a/libapp.so"])
    apk_out = str(tmp_path / "out.apk")
    apk.repackage(src, apk_out, None, cipher="wbaes", no_sign=True, logger=lambda *_: None)
    with zipfile.ZipFile(apk_out) as z:
        assert z.getinfo("lib/arm64-v8a/libapp.so").compress_type == zipfile.ZIP_STORED


# ---- 5. a bundle is never signed, and that is not a degradation --------------------------
def test_a_bundle_is_left_unsigned_without_touching_a_signing_tool(tmp_path, monkeypatch):
    """Unsigned BY DESIGN, not "unsigned because a tool was missing". If this ever starts
    resolving apksigner it will also start generating ~/.sopack/debug.keystore on a machine whose
    output can never be signed with it - the same mistake the apksigner-before-keystore ordering
    was introduced to prevent."""
    _fake_wbaes(monkeypatch, sealed=[])

    def _boom(*a, **k):                                     # pragma: no cover - must not run
        raise AssertionError("the AAB path must not reach a signing tool")

    monkeypatch.setattr(apk, "apksigner_cmd", _boom)
    monkeypatch.setattr(apk, "ensure_keystore", _boom)

    src = mkaab(tmp_path / "in.aab", ["base/lib/arm64-v8a/libapp.so"])
    out = str(tmp_path / "out.aab")
    res = apk.repackage(src, out, None, cipher="wbaes",
                        keystore=apk.KeystoreInfo(path=str(tmp_path / "never.keystore")),
                        logger=lambda *_: None)
    assert res.signed is False
    assert res.container == "aab"
    assert os.path.exists(out)
    assert not os.path.exists(tmp_path / "never.keystore")


def test_the_old_jar_signature_is_dropped_but_module_meta_inf_survives(tmp_path, monkeypatch):
    """MANIFEST.MF carries a SHA-256 digest of every entry, so once a library is rewritten the
    signature can never verify again - keeping it turns "unsigned, go sign it" into a confusing
    jarsigner failure. `<module>/root/META-INF/` is unrelated app data and must pass through."""
    _fake_wbaes(monkeypatch, sealed=[])
    src = mkaab(tmp_path / "in.aab", ["base/lib/arm64-v8a/libapp.so"])
    with zipfile.ZipFile(src, "a") as z:
        z.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
        z.writestr("META-INF/UPLOAD.SF", b"Signature-Version: 1.0\n")
        z.writestr("META-INF/UPLOAD.RSA", b"\x30\x82")
        z.writestr("base/root/META-INF/viewfinder.kotlin_module", b"kotlin")

    out = str(tmp_path / "out.aab")
    apk.repackage(src, out, None, cipher="wbaes", logger=lambda *_: None)
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
    assert not [n for n in names if n.startswith("META-INF/")]
    assert "base/root/META-INF/viewfinder.kotlin_module" in names


# ---- 6. the run record, and the CLI surface ----------------------------------------------
def test_the_cli_records_the_container_and_says_it_is_unsigned(tmp_path, monkeypatch, capsys):
    _fake_wbaes(monkeypatch, sealed=[])
    monkeypatch.setenv(diag.ENV_LOG_DIR, str(tmp_path / "logs"))
    monkeypatch.delenv(diag.ENV_RUN_TAG, raising=False)
    src = mkaab(tmp_path / "in.aab", ["base/lib/arm64-v8a/libapp.so"])
    out = str(tmp_path / "out.aab")
    try:
        code = cli.main(["pack", src, "-o", out])
    finally:
        diag.reset()
    assert code == 0

    stdout = capsys.readouterr().out
    assert "input: Android App Bundle (detected)" in stdout
    assert "libs=ALL <module>/lib/<abi>/*.so" in stdout
    assert "UNSIGNED, by design" in stdout
    assert "jarsigner" in stdout
    assert "apksigner sign" not in stdout, "apksigner cannot read a bundle; do not suggest it"

    runs = sorted((tmp_path / "logs" / "runs").iterdir())
    assert len(runs) == 1
    # The run id ends in the input's stem with the extension REMOVED, not turned into "_aab".
    assert runs[0].name.endswith("-in")
    rec = json.loads((runs[0] / "report.json").read_text())
    assert rec["container"] == "aab"
    assert rec["signed"] is False
    # per_abi must key on the real ABI. Keyed on entry.split("/")[1] it would say "lib".
    assert set(rec["per_abi"]) == {"arm64-v8a"}

    index = (tmp_path / "logs" / "index.jsonl").read_text().splitlines()
    assert json.loads(index[-1])["container"] == "aab"


def test_a_mismatched_output_extension_warns_but_packs(tmp_path, monkeypatch, capsys):
    """A warning, never an error - the format is decided by content, so the name is cosmetic. But
    silently writing a bundle to something called .apk is how it ends up at `adb install`."""
    _fake_wbaes(monkeypatch, sealed=[])
    monkeypatch.setenv(diag.ENV_LOG_DIR, str(tmp_path / "logs"))
    monkeypatch.delenv(diag.ENV_RUN_TAG, raising=False)
    src = mkaab(tmp_path / "in.aab", ["base/lib/arm64-v8a/libapp.so"])
    try:
        code = cli.main(["pack", src, "-o", str(tmp_path / "out.apk")])
    finally:
        diag.reset()
    assert code == 0
    assert "the input is an AAB but the output is named out.apk" in capsys.readouterr().err
