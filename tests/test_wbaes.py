"""`--cipher wbaes` injection tests.

Two tiers, deliberately:

* Everything driven by `tests/fixtures/mini_arm64.so` runs with **no setup at all** — it is a
  committed 50 KB aarch64 `.so` built for this purpose (see `mini_arm64.c` for the three
  properties it must keep). That covers the guards and the `.dynstr` re-sort behaviour that
  the whole mode depends on.
* The two full-injection tests additionally need a **host** `wb_keygen`, because `--cipher
  wbaes` seals a real white-box blob and there is no way to fake that meaningfully. They skip
  without one.

The on-device decrypt is validated separately: the host round-trip probe in
`docs/wbaes-verification.md` Phase 3, then Phase 6 on a device.
"""
import os
import pathlib
import shutil
import subprocess

import lief
import pytest

from sopack import cipher, elf_inject
from sopack.elf_inject import InjectError, _dynsym_names, _extract_region, _needed_via_strtab
from sopack.provision import find_wb_keygen
from sopack.rt_meta import HELPER_BUILD_MARKER, WRAPPED_KEY_BYTES, Region

lief.logging.disable()

ROOT = os.path.dirname(os.path.dirname(__file__))

# Purpose-built and committed, so these tests are not at the mercy of a local APK. One file
# serves as both injection target and mock helper skeleton: it has no DT_NEEDED, so it passes
# _emit_helper's bionic-only dependency check.
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "mini_arm64.so")

# Optional: point at a real library to exercise the same paths at realistic scale.
_BIG_SO = os.environ.get("SOPACK_TEST_ARM64_SO",
                         os.path.join(ROOT, "assets", "libvosWrapperEx-arm64.so"))


def _have_wb_keygen() -> bool:
    try:
        find_wb_keygen(None)
        return True
    except FileNotFoundError:
        return False


# Separate conditions, so a skip says which one actually fired rather than listing four.
_needs_wb_keygen = pytest.mark.skipif(
    not _have_wb_keygen(), reason="needs a host wb_keygen (SOPACK_WBKEYGEN or on PATH)")
_needs_readelf = pytest.mark.skipif(
    shutil.which("readelf") is None, reason="needs readelf")


def _marked_skeleton(tmp_path, src=FIXTURE) -> pathlib.Path:
    """A usable mock skeleton: `src` plus the build marker appended. Trailing bytes past the
    last section are ignored by LIEF and by the loader, so this is a valid `.so`. Returns a
    Path, matching what the real `helper_skeleton_path` hands back."""
    path = tmp_path / "mock_skeleton.so"
    shutil.copyfile(src, path)
    with open(path, "ab") as f:
        f.write(HELPER_BUILD_MARKER)
    return path


def _load_aligns(path: str) -> set[str]:
    out = subprocess.run(["readelf", "-lW", path], capture_output=True, text=True).stdout
    return {ln.split()[-1] for ln in out.splitlines() if " LOAD " in ln}


# ---- the fact the whole mode rests on, and the two pack-time guards -------------------

def test_lief_reorders_dynstr_on_write(tmp_path):
    """`_effective_strtab` exists because LIEF rebuilds `.dynstr` **sorted** during `write()`
    and rewrites every `st_name` to match. Pin that behaviour directly: if a future LIEF
    stopped reordering, this test failing is the signal that the appended-copy dance can be
    simplified — and if it still reorders, taking the table from the pre-write section is
    still wrong. See docs/architecture.md §11f."""
    pre = bytes(lief.parse(FIXTURE).get_section(".dynstr").content)
    b = lief.parse(FIXTURE)
    seg = lief.ELF.Segment()
    seg.type = elf_inject._seg_type_load()
    seg.flags = elf_inject._seg_flags_r()
    seg.alignment = elf_inject.SEGMENT_ALIGN
    seg.content = [0] * 4096
    b.add(seg)
    out = str(tmp_path / "written.so")
    b.write(out)

    post = elf_inject._effective_strtab(out)
    assert pre != post, "LIEF no longer reorders .dynstr — revisit _effective_strtab"
    # same strings, different order: that is exactly what desynchronises the offsets
    assert sorted(pre.split(b"\x00")) == sorted(post.split(b"\x00"))


def test_emit_helper_refuses_a_skeleton_without_the_build_marker(monkeypatch, tmp_path):
    """A stale skeleton fails open SILENTLY on device: its ctor's region-version gate finds
    nothing, so the target runs still-encrypted `.text`. This guard turns that into a
    pack-time error."""
    stale = tmp_path / "stale_skeleton.so"
    shutil.copyfile(FIXTURE, stale)              # a real .so, just without the marker
    monkeypatch.setattr(elf_inject, "helper_skeleton_path", lambda abi: stale)
    with pytest.raises(InjectError, match="build marker"):
        elf_inject._emit_helper("arm64-v8a", "libsopk_rt_x.so", b"SRTR" + bytes(92),
                                str(tmp_path / "helper.so"))


def test_emit_helper_refuses_a_skeleton_with_unresolved_wbc_symbols(monkeypatch, tmp_path):
    """A `-shared` link permits unresolved symbols, so a skeleton built against a 1.x
    libwbcrypto.a links CLEANLY with `wbc_unwrap_key`/`wbc_wipe` left as UND imports. bionic
    then cannot load the helper, so `dlopen` of the TARGET fails with it, and the app crashes
    in whatever was loading the target. This shipped in a real APK.

    The unresolved symbols are injected rather than taken from a checked-in binary, so the
    test exercises the guard itself instead of whichever skeleton happens to be present."""
    monkeypatch.setattr(elf_inject, "helper_skeleton_path",
                        lambda abi: _marked_skeleton(tmp_path))
    monkeypatch.setattr(elf_inject, "_undefined_dynsyms",
                        lambda path: ["memcpy", "wbc_unwrap_key", "wbc_wipe"])
    with pytest.raises(InjectError, match="instead of defining them"):
        elf_inject._emit_helper("arm64-v8a", "libsopk_rt_x.so", b"SRTR" + bytes(92),
                                str(tmp_path / "helper.so"))


def test_dynsym_count_handles_a_gnu_hash_only_lib():
    """The symbol count feeds every symbol comparison, so an under-count would silently
    compare truncated lists. `DT_GNU_HASH`-only is the branch that does not go through
    `DT_HASH`'s `nchain`; the fixture is such a library. Cross-check against the section
    header, which is independent of the dynamic tags."""
    v = elf_inject._LoaderView(FIXTURE)
    assert 4 not in v.tags, "fixture gained a DT_HASH — it no longer covers this branch"
    assert 0x6FFFFEF5 in v.tags
    assert v.dynsym_count() == lief.parse(FIXTURE).get_section(".dynsym").size // 24
    assert len(_dynsym_names(FIXTURE)) == 3


def test_fixture_keeps_the_properties_the_tests_depend_on():
    """The fixture is only useful while it keeps all three properties `mini_arm64.c`
    documents. A regenerated fixture that lost one would make the tests above pass while
    testing nothing."""
    names = _dynsym_names(FIXTURE)
    assert names != sorted(names), "alphabetical == file order: .dynstr re-sort is invisible"
    assert not elf_inject._needed_names(lief.parse(FIXTURE)), "fixture gained a DT_NEEDED"
    assert lief.parse(FIXTURE).get_section(".text").size > 16384, ".text must span >1 page"


# ---- full injection (needs a host wb_keygen to seal a real blob) ----------------------

@_needs_wb_keygen
def test_self_verify_catches_a_desynced_string_table(monkeypatch, tmp_path):
    """Reintroduce the shipped bug — take `.dynstr` from the PRE-write section, as the
    original code did — and assert the pack FAILS rather than producing an APK that loads and
    then crashes. Tests the guard, not the fix, so a refactor cannot quietly drop it."""
    monkeypatch.setattr(elf_inject, "helper_skeleton_path",
                        lambda abi: _marked_skeleton(tmp_path))
    monkeypatch.setattr(elf_inject, "_effective_strtab",
                        lambda path: bytes(lief.parse(FIXTURE).get_section(".dynstr").content))
    with pytest.raises(InjectError, match="dynamic symbol names"):
        elf_inject.inject_so(FIXTURE, str(tmp_path / "out.so"), "arm64-v8a",
                             cipher="wbaes", target_name="libmini_arm64.so")


@_needs_wb_keygen
@_needs_readelf
@pytest.mark.parametrize("target", ["fixture", "big"])
def test_wbaes_injection_surgery(monkeypatch, tmp_path, target):
    """The real thing: seal a long-term key, wrap a session key, ChaCha20-encrypt `.text`,
    add the DT_NEEDED by raw surgery (NOT LIEF `add_library`, which spills 4 KB segments on
    tight libraries), and emit the per-target helper carrying the region."""
    src = FIXTURE if target == "fixture" else _BIG_SO
    if not os.path.exists(src):
        pytest.skip(f"no {target} target at {src}")
    monkeypatch.setattr(elf_inject, "helper_skeleton_path",
                        lambda abi: _marked_skeleton(tmp_path, src))
    target_name = os.path.basename(src)
    out = str(tmp_path / "out.so")

    ir = elf_inject.inject_so(src, out, "arm64-v8a", cipher="wbaes", target_name=target_name)

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

    # The invariant this mode broke on device: the injection must not disturb a single one of
    # the target's exported symbol names. Resolved the way dlsym does, via DT_STRTAB.
    assert _dynsym_names(out) == _dynsym_names(src)

    # `.text` really is ciphertext: different from the original and high-entropy.
    sec = lief.parse(out).get_section(".text")
    with open(src, "rb") as f0, open(out, "rb") as f1:
        f0.seek(int(sec.file_offset)); orig = f0.read(int(sec.size))
        f1.seek(int(sec.file_offset)); enc = f1.read(int(sec.size))
    assert enc != orig
    assert len(set(enc)) > 200                  # ciphertext uses ~all byte values
