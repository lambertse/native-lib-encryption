"""wbaes injection surgery test.

Exercises the real `--cipher wbaes` injection on an arm64 target: sealing a long-term key
via a HOST wb_keygen, wrapping a session key under it, `.text` ChaCha20 encryption, the raw
DT_NEEDED injection (append a 16 KB-aligned .dynstr copy + repoint DT_STRTAB + in-place
DT_NEEDED — NOT LIEF add_library, which spills 4 KB segments on tight libs), and the
emitted per-target helper carrying the metadata region.

Skipped unless a runnable host wb_keygen is available (SOPACK_WBKEYGEN or on PATH) and an
arm64 skeleton/target is present. The on-device decrypt is validated separately (the host
white-box round-trip probe in docs/wbaes-verification.md, then on-device). We use an
existing bionic-only arm64 .so as both the mock helper skeleton and the injection target —
with the build marker appended, since _emit_helper (correctly) refuses a skeleton without
one."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import pytest

HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from sopack import cipher, elf_inject          # noqa: E402
from sopack.elf_inject import (InjectError, _dynsym_names, _extract_region,  # noqa: E402
                               _needed_via_strtab)
from sopack.rt_meta import (HELPER_BUILD_MARKER, WRAPPED_KEY_BYTES,  # noqa: E402
                            Region)
from sopack.provision import find_wb_keygen    # noqa: E402

# A real arm64 .so whose DT_NEEDED are all bionic (valid mock skeleton) and which also
# serves as the injection target. Override via SOPACK_TEST_ARM64_SO.
_DEFAULT_SO = os.path.join(ROOT, "assets", "libvosWrapperEx-arm64.so")
_ARM64_SO = os.environ.get("SOPACK_TEST_ARM64_SO", _DEFAULT_SO)


def _have_wb_keygen() -> bool:
    try:
        find_wb_keygen(None)
        return True
    except FileNotFoundError:
        return False


# Only the full injection needs a host wb_keygen; the build-marker guard below does not, and
# is worth running everywhere since it is what stops a stale skeleton shipping.
_needs_toolchain = pytest.mark.skipif(
    not os.path.exists(_ARM64_SO) or shutil.which("readelf") is None
    or not _have_wb_keygen(),
    reason="needs a host wb_keygen (SOPACK_WBKEYGEN/PATH) + an arm64 .so + readelf",
)


def _load_aligns(path: str) -> set[str]:
    out = subprocess.run(["readelf", "-lW", path], capture_output=True, text=True).stdout
    return {ln.split()[-1] for ln in out.splitlines() if " LOAD " in ln}


_VSA_APK = os.path.join(ROOT, "assets", "vsa.apk")


@pytest.mark.skipif(not os.path.exists(_VSA_APK), reason="needs assets/vsa.apk")
def test_dynsym_count_handles_gnu_hash_only_libs(tmp_path):
    """_dynsym_names' symbol count comes from the loader's hash table, and the DT_GNU_HASH
    branch is the one no other test reaches — both libapp.so and libvosWrapperEx have DT_HASH,
    so it would sit unexercised while silently deciding whether the symbol comparison compares
    full lists or truncated ones. Cross-check it against the section-header count on real
    GNU_HASH-only libraries."""
    import zipfile

    import lief
    lief.logging.disable()
    from sopack.elf_inject import _LoaderView

    z = zipfile.ZipFile(_VSA_APK)
    checked = 0
    for entry in z.namelist():
        if not (entry.startswith("lib/arm64-v8a/") and entry.endswith(".so")):
            continue
        p = tmp_path / os.path.basename(entry)
        p.write_bytes(z.read(entry))
        v = _LoaderView(str(p))
        if 4 in v.tags:                       # DT_HASH present -> not the branch under test
            continue
        if 0x6FFFFEF5 not in v.tags:
            continue
        dynsym = lief.parse(str(p)).get_section(".dynsym")
        assert dynsym is not None
        assert v.dynsym_count() == dynsym.size // 24, entry
        assert len(_dynsym_names(str(p))) > 0, entry
        checked += 1
    assert checked, "no GNU_HASH-only arm64 lib found — this test asserted nothing"


_REPO_SKELETON = os.path.join(ROOT, "sopack", "stubs", "sopk_rt_arm64-v8a.so")


@pytest.mark.skipif(not os.path.exists(_REPO_SKELETON), reason="no arm64 skeleton in the repo")
def test_emit_helper_refuses_a_skeleton_with_unresolved_wbc_symbols(monkeypatch, tmp_path):
    """A `-shared` link permits unresolved symbols, so a skeleton built against a 1.x
    libwbcrypto.a links CLEANLY with wbc_unwrap_key/wbc_wipe left as UND imports. bionic then
    cannot load the helper, so dlopen of the TARGET fails too, and the app crashes in whatever
    was loading it. This shipped in a real APK. Uses the repo's own skeleton, which is exactly
    that build (marker appended so the marker guard is not what fires)."""
    marked = tmp_path / "skel.so"
    shutil.copyfile(_REPO_SKELETON, marked)
    with open(marked, "ab") as f:
        f.write(HELPER_BUILD_MARKER)
    unresolved = [s for s in elf_inject._undefined_dynsyms(str(marked))
                  if s.startswith(("wbc_", "sodium_"))]
    if not unresolved:
        pytest.skip("repo skeleton has been rebuilt against 2.0.0 — nothing to detect")
    monkeypatch.setattr(elf_inject, "helper_skeleton_path", lambda abi: marked)
    with pytest.raises(InjectError, match="instead of defining them"):
        elf_inject._emit_helper("arm64-v8a", "libsopk_rt_x.so", b"SRTR" + bytes(92),
                                str(tmp_path / "helper.so"))


def _mock_skeleton(td: str) -> str:
    """The real skeleton is built by hand with the NDK, which we do not have here. Use the
    stand-in .so with the build marker appended so it passes _emit_helper's guard (trailing
    bytes past the last section are ignored by both LIEF and the loader)."""
    path = os.path.join(td, "mock_skeleton.so")
    shutil.copyfile(_ARM64_SO, path)
    with open(path, "ab") as f:
        f.write(HELPER_BUILD_MARKER)
    return path


def test_emit_helper_refuses_a_skeleton_without_the_build_marker(monkeypatch, tmp_path):
    """A stale skeleton fails open SILENTLY on device (its ctor's version gate finds no
    region, so the target runs encrypted .text and SIGILLs). This guard is what turns that
    into a pack-time error, so it needs a test of its own."""
    stale = tmp_path / "stale_skeleton.so"
    shutil.copyfile(_ARM64_SO, stale)            # a real .so, just without the marker
    monkeypatch.setattr(elf_inject, "helper_skeleton_path", lambda abi: stale)
    with pytest.raises(InjectError, match="build marker"):
        elf_inject._emit_helper("arm64-v8a", "libsopk_rt_x.so", b"SRTR" + bytes(92),
                                str(tmp_path / "helper.so"))


@_needs_toolchain
def test_self_verify_catches_a_desynced_string_table(monkeypatch, tmp_path):
    """Reintroduce the shipped bug — use the PRE-write .dynstr, as the original code did — and
    assert the pack fails instead of producing an APK that loads and then crashes. This tests
    the guard rather than the fix, so a future refactor cannot quietly drop it."""
    import lief
    skeleton = _mock_skeleton(str(tmp_path))
    monkeypatch.setattr(elf_inject, "helper_skeleton_path",
                        lambda abi: pathlib.Path(skeleton))
    monkeypatch.setattr(elf_inject, "_effective_strtab",
                        lambda path: bytes(lief.parse(_ARM64_SO).get_section(".dynstr").content))
    with pytest.raises(InjectError, match="dynamic symbol names"):
        elf_inject.inject_so(_ARM64_SO, str(tmp_path / "out.so"), "arm64-v8a",
                             cipher="wbaes", target_name=os.path.basename(_ARM64_SO))


@_needs_toolchain
def test_wbaes_injection_surgery(monkeypatch, tmp_path):
    skeleton = _mock_skeleton(str(tmp_path))
    monkeypatch.setattr(elf_inject, "helper_skeleton_path",
                        lambda abi: pathlib.Path(skeleton))
    target_name = os.path.basename(_ARM64_SO)

    with tempfile.TemporaryDirectory(prefix="wbaes-test-") as td:
        out = os.path.join(td, "out.so")
        ir = elf_inject.inject_so(_ARM64_SO, out, "arm64-v8a",
                                  cipher="wbaes", target_name=target_name)

        # self-verify passed (inject_so raises otherwise). Sanity the result.
        assert ir.strategy == "DT_NEEDED-wbaes"
        assert ir.helper_soname.startswith("libsopk_rt_")
        assert os.path.exists(ir.helper_path)

        # every LOAD segment stays 16 KB-aligned in BOTH artifacts (no 4 KB spill).
        for p in (out, ir.helper_path):
            for a in _load_aligns(p):
                assert int(a, 16) % 16384 == 0, f"{p}: 4 KB LOAD align {a}"

        # DT_NEEDED resolves (via DT_STRTAB, as bionic does) to the helper soname.
        assert ir.helper_soname in _needed_via_strtab(out)

        # the emitted helper's region round-trips and describes this target.
        r = Region.unpack(_extract_region(ir.helper_path))
        assert r.text_rva == ir.text_rva and r.text_size == ir.text_size
        assert r.soname.decode() == target_name
        assert len(r.blob) > 100_000        # a sealed white-box blob is hundreds of KB
        # the whitened passphrase de-whitens (self-inverse, keyed off the blob).
        assert cipher.whiten_pass(r.wpass, r.blob).isascii()

        # the key-wrap fields the device reads as fixed-size arrays.
        assert len(r.wrapped) == WRAPPED_KEY_BYTES
        assert r.wrapped[:16] != bytes(16)          # wrap IV is random, not zero
        assert r.wrapped[16:] != bytes(32)
        assert len(r.nonce16) == 16 and r.nonce16[12:] == b"\x00\x00\x00\x00"

        # THE INVARIANT THIS MODE BROKE ON DEVICE: injecting the DT_NEEDED must not disturb
        # a single one of the target's exported symbol names. It appends a copy of .dynstr
        # and repoints DT_STRTAB at it, and LIEF re-sorts .dynstr during write() while
        # rewriting every st_name to match — so a copy taken BEFORE the write makes every
        # offset land mid-string. That shipped an APK where dlsym() returned NULL for every
        # symbol; Flutter then null-dereferenced its Dart snapshot pointers and SIGSEGV'd in
        # performNativeAttach. Resolved the way dlsym does, via DT_STRTAB, not sections.
        assert _dynsym_names(out) == _dynsym_names(_ARM64_SO)

        # `.text` really is ChaCha20 ciphertext, not plaintext: it must differ from the
        # original and look high-entropy.
        with open(_ARM64_SO, "rb") as f0, open(out, "rb") as f1:
            import lief
            sec = lief.parse(out).get_section(".text")
            f0.seek(int(sec.file_offset)); orig = f0.read(int(sec.size))
            f1.seek(int(sec.file_offset)); enc = f1.read(int(sec.size))
        assert enc != orig
        assert len(set(enc)) > 200                  # ciphertext uses ~all byte values


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
