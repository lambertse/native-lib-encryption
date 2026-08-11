"""`--cipher wbaes` injection tests.

Three tiers, deliberately:

* Everything driven by `tests/fixtures/mini_arm64.so` runs with **no setup at all** — it is a
  committed 50 KB aarch64 `.so` built for this purpose (see `mini_arm64.c` for the three
  properties it must keep). That covers the guards and the `.dynstr` re-sort behaviour that
  the whole mode depends on.
* The two full-injection tests additionally need a **host** `wb_keygen`, because `--cipher
  wbaes` seals a real white-box blob and there is no way to fake that meaningfully. They skip
  without one.
* The strip tests need a compiler that emits **ELF** — not merely a compiler. macOS `cc`
  produces Mach-O, so there `_elf_cc` falls back to the NDK's clang if `ANDROID_NDK_HOME` is
  set, and they skip if it is not.

The on-device decrypt is validated separately: the host round-trip probe in
`docs/wbaes-verification.md` Phase 3, then Phase 6 on a device.
"""
import functools
import glob
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile

import lief
import pytest

from sopack import cipher, elf_inject
from sopack.elf_inject import InjectError, _dynsym_names, _extract_region, _needed_via_strtab
from sopack.provision import find_wb_keygen
from sopack.rt_meta import (HELPER_BUILD_MARKER, PROVIDER_BUILD_MARKER, PROVIDER_ENTRY,
                            PROVIDER_SONAME, WB_REGION_MAGIC, WRAPPED_KEY_BYTES,
                            TargetRegion, WbRegion)

lief.logging.disable()

ROOT = os.path.dirname(os.path.dirname(__file__))

# Purpose-built and committed, so these tests are not at the mercy of a local APK. One file
# serves as both injection target and mock helper skeleton: it has no DT_NEEDED, so it passes
# _emit_helper's bionic-only dependency check.
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "mini_arm64.so")


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


def _marked_provider(tmp_path, src=FIXTURE, soname=None) -> pathlib.Path:
    """Mock provider skeleton: `src` with a real DT_SONAME plus the PROVIDER build marker.

    The soname is set with LIEF rather than faked, because it is genuinely load-bearing: each
    thin helper's DT_NEEDED string is whatever the linker recorded here, so `emit_provider`
    asserts it instead of setting it. The two markers differ on purpose, so a provider carrying
    the helper's marker (or vice versa) is refused."""
    path = tmp_path / "mock_provider.so"
    b = lief.parse(src)
    elf_inject._set_soname(b, soname or PROVIDER_SONAME)
    b.write(str(path))
    with open(path, "ab") as f:
        f.write(PROVIDER_BUILD_MARKER)
    return path


def _wire_provider(monkeypatch):
    """Make a mock provider satisfy the guards a real linker would satisfy: it must EXPORT
    sopk_wb_k. The expectation genuinely inverts for this artifact — a thin helper exports
    nothing — so this is patched rather than faked into the fixture.

    Discriminates by the file's own DT_SONAME, not its path, so it covers both the skeleton and
    the emitted copy (whose filename the packer chooses) while leaving the thin helper in the
    same pack checked normally. A blanket patch would hide the very asymmetry being tested."""
    real = elf_inject._exported_dynsyms

    def exported(path):
        b = lief.parse(str(path))
        if b is not None and elf_inject._dynamic_soname(b) == PROVIDER_SONAME:
            return [PROVIDER_ENTRY]
        return real(path)

    monkeypatch.setattr(elf_inject, "_exported_dynsyms", exported)


def _target_region(soname: bytes = b"libtarget.so") -> bytes:
    """A structurally valid v3 TARGET region. The fixtures cannot carry a real one, and a bare
    magic + padding no longer parses now that the two kinds are distinguished."""
    return TargetRegion(text_rva=0x1000, text_size=64, wrapped=bytes(48),
                        nonce16=bytes(16), soname=soname).pack()


def _wire_thin(monkeypatch, undefined=(), needed=()):
    """Make a mock thin-helper skeleton satisfy the v3 pairing guards.

    Since the provider split, a thin helper must DT_NEEDED libsopk_wb.so and import sopk_wb_k —
    real linker output that a checked-in fixture cannot have. Tests that want to exercise a
    DIFFERENT guard patch these so the pairing checks pass and the guard under test is what
    fires; pass `undefined`/`needed` to add the symbols that test cares about."""
    real_needed = elf_inject._needed_names

    def needed_names(binary):
        # Only a THIN helper gains the provider dependency. The provider itself must stay
        # bionic-only, and a blanket patch would hide that asymmetry — which is one of the
        # things the guards are for.
        if elf_inject._dynamic_soname(binary) == PROVIDER_SONAME:
            return real_needed(binary)
        return [PROVIDER_SONAME, *needed]

    monkeypatch.setattr(elf_inject, "_undefined_dynsyms",
                        lambda path: [PROVIDER_ENTRY, *undefined])
    monkeypatch.setattr(elf_inject, "_needed_names", needed_names)


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
        elf_inject._emit_helper("arm64-v8a", "libsopk_rt_x.so", _target_region(),
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
    _wire_thin(monkeypatch, undefined=["memcpy", "wbc_unwrap_key", "wbc_wipe"])
    # Since v3 a thin helper must not reference the white-box AT ALL, so the message differs
    # from the provider's "imports … instead of defining them".
    with pytest.raises(InjectError, match="must not touch the white-box"):
        elf_inject._emit_helper("arm64-v8a", "libsopk_rt_x.so", _target_region(),
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


def test_16k_failure_blames_the_input_when_the_input_is_at_fault(tmp_path):
    """`_assert_16k_and_no_textrel` fires on the packed output, but the offending LOAD segment is
    often inherited from the input — and then no packer fix can help. A bare
    "LOAD seg align 4096" sent a reader hunting for an injection bug that was not there, so the
    two causes must read differently.

    The 4 KB input is synthesised by rewriting p_align in the fixture's program headers, so this
    needs no compiler."""
    src = tmp_path / "input_4k.so"
    data = bytearray(open(FIXTURE, "rb").read())
    e_phoff = int.from_bytes(data[0x20:0x28], "little")
    e_phentsize = int.from_bytes(data[0x36:0x38], "little")
    e_phnum = int.from_bytes(data[0x38:0x3A], "little")
    patched = 0
    for i in range(e_phnum):
        p = e_phoff + i * e_phentsize
        if int.from_bytes(data[p:p + 4], "little") == 1:            # PT_LOAD
            data[p + 0x30:p + 0x38] = (4096).to_bytes(8, "little")  # p_align
            patched += 1
    assert patched, "fixture has no PT_LOAD to patch"
    src.write_bytes(bytes(data))

    assert elf_inject._16k_violations(lief.parse(str(src))), "patching p_align had no effect"
    with pytest.raises(InjectError, match="not 16 KB-page compatible to begin with"):
        elf_inject._assert_16k_and_no_textrel(lief.parse(str(src)), "arm64-v8a",
                                              orig_path=str(src))
    # ...and with no orig_path to compare against, it must NOT blame the input
    with pytest.raises(InjectError, match="this one is ours"):
        elf_inject._assert_16k_and_no_textrel(lief.parse(str(src)), "arm64-v8a")


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
    _wire_thin(monkeypatch)
    monkeypatch.setattr(elf_inject, "_effective_strtab",
                        lambda path: bytes(lief.parse(FIXTURE).get_section(".dynstr").content))
    with pytest.raises(InjectError, match="dynamic symbol names"):
        elf_inject.inject_so(FIXTURE, str(tmp_path / "out.so"), "arm64-v8a",
                             cipher="wbaes", target_name="libmini_arm64.so")


@_needs_wb_keygen
@_needs_readelf
def test_wbaes_injection_surgery(monkeypatch, tmp_path):
    """The real thing: seal a long-term key, wrap a session key, ChaCha20-encrypt `.text`,
    add the DT_NEEDED by raw surgery (NOT LIEF `add_library`, which spills 4 KB segments on
    tight libraries), and emit the per-target helper carrying the region.

    Runs against the committed fixture only. A variant against a large real library used to run
    from `assets/`, but that directory is gitignored, so what it tested varied by machine — and
    some LIEF versions add a 4 KB-aligned segment to a big library, failing the 16 KB assertion
    below for reasons that are neither sopack's nor the test's. See docs/troubleshooting.md."""
    src = FIXTURE
    monkeypatch.setattr(elf_inject, "helper_skeleton_path",
                        lambda abi: _marked_skeleton(tmp_path, src))
    _wire_thin(monkeypatch)
    # Since v3 a standalone inject_so also emits the shared provider, so both mock skeletons
    # have to be in place.
    provider = _marked_provider(tmp_path, src)
    monkeypatch.setattr(elf_inject, "provider_skeleton_path", lambda abi: provider)
    _wire_provider(monkeypatch)
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
    r = TargetRegion.unpack(_extract_region(ir.helper_path))
    assert r.text_rva == ir.text_rva and r.text_size == ir.text_size
    assert r.soname.decode() == target_name

    # The blob and passphrase live in the SHARED provider now, not here. Assert both halves of
    # that split: the thin helper is small and blob-free, and the provider carries the real one.
    assert ir.provider_path and os.path.exists(ir.provider_path)
    assert os.path.getsize(ir.helper_path) < 100_000, (
        "thin helper looks like it still carries the sealed blob")
    w = WbRegion.unpack(_extract_region(ir.provider_path, WB_REGION_MAGIC))
    assert len(w.blob) > 100_000        # a sealed white-box blob is hundreds of KB
    # the whitened passphrase de-whitens (self-inverse, keyed off the blob).
    assert cipher.whiten_pass(w.wpass, w.blob).isascii()
    # the provider keeps the soname every thin helper records as its DT_NEEDED. Only this half
    # is checkable here: the helper's actual DT_NEEDED is written by the LINKER at Phase-4 time,
    # and this mock skeleton has none on disk (the guards see a monkeypatched value). Phase 4's
    # PASS checks verify the real pairing on a real skeleton.
    assert elf_inject._dynamic_soname(lief.parse(ir.provider_path)) == PROVIDER_SONAME

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


# ---- the strip, and the release-posture gates ------------------------------------------
#
# All of this exists because a static-analysis report on a shipped APK reconstructed the whole
# design in about an hour, and named the unstripped, tracing helper as the reason. The build
# script could already produce a correct release helper; nothing refused an incorrect one.

_HOST_CC = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")

_HOST_SRC = """
static const char hidden_symbol_name[] = "RODATA-MUST-SURVIVE";
int host_answer(void) { return 4242; }
const char *host_marker(void) { return hidden_symbol_name; }
"""

_BUILD_FLAGS = ("-g", "-O1", "-fPIC", "-shared")     # -g: there must be something to strip


def _ndk_clang():
    """The NDK's clang, if the environment points at an NDK. It cross-compiles ELF from any
    host, which is the whole reason it is here — see `_elf_cc`. The prebuilt directory is
    globbed rather than derived from `uname`, because on Apple Silicon the only toolchain an
    NDK ships is `darwin-x86_64`, run under Rosetta."""
    root = (os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
            or os.environ.get("NDK"))
    if not root:
        return None
    found = sorted(glob.glob(
        os.path.join(root, "toolchains", "llvm", "prebuilt", "*", "bin", "clang")))
    return found[0] if found else None


@functools.lru_cache(maxsize=None)
def _elf_cc():
    """An argv prefix for a compiler that emits **ELF**, or None. Cached: it compiles to find out.

    Having a compiler is not enough for ELF surgery. On macOS `cc -shared` emits a Mach-O dylib
    (the `.so` name is cosmetic): LIEF parses it as a `MachO.Binary`, it has no `.symtab`
    *section* because its symbols live in `LC_SYMTAB`/`__LINKEDIT`, `-g` leaves the DWARF in the
    `.o` files instead of the linked image, and `_strip_nonalloc` refuses it on the `\\x7fELF`
    check. All three assumptions these tests make are wrong there at once.

    Prefer the host's own compiler when it emits ELF — that fixture is also *loadable*, which
    `_elf_so(native=True)` needs — and otherwise cross-compile for arm64 Android, which is the
    target the shipped helper is built for anyway. Probes the output rather than the platform,
    so any host that does emit ELF is used as-is."""
    candidates = [[_HOST_CC], [_ndk_clang(), "--target=aarch64-linux-android24"]]
    with tempfile.TemporaryDirectory() as td:
        src = pathlib.Path(td) / "probe.c"
        src.write_text(_HOST_SRC)
        out = pathlib.Path(td) / "probe.so"
        for argv in candidates:
            if argv[0] is None:
                continue
            r = subprocess.run([*argv, *_BUILD_FLAGS, "-o", str(out), str(src)],
                               capture_output=True)
            if r.returncode == 0 and out.exists() and out.read_bytes()[:4] == b"\x7fELF":
                return tuple(argv)
    return None


def _elf_so(tmp_path, name="hostlib.so", *, native=False):
    """An ELF `.so` built WITH debug info, so there is something to strip.

    `native=True` additionally demands one this host can `dlopen`: a cross-compiled
    aarch64-android library satisfies every other test here, but nothing local can load it."""
    argv = _elf_cc()
    if argv is None or (native and argv[0] != _HOST_CC):
        pytest.skip(
            "no compiler emitting ELF: host cc is absent or emits Mach-O, and no NDK to "
            "cross-compile with (set ANDROID_NDK_HOME)" if argv is None else
            f"only a cross-compiler is available ({argv[0]}) and this test must dlopen its "
            "output")
    src = tmp_path / "hostlib.c"
    src.write_text(_HOST_SRC)
    out = tmp_path / name
    subprocess.run([*argv, *_BUILD_FLAGS, "-o", str(out), str(src)], check=True)
    return out


def test_strip_removes_debug_and_symbols_but_keeps_the_loader_view(tmp_path):
    """The strip must delete exactly the sections the loader never maps, and nothing else.
    `.dynsym`/`.dynstr`/`.shstrtab` and a non-zero `e_shnum` all have to survive: bionic on
    Android 14+ rejects a library with no section headers, which is why the rejected §Method 3
    (zeroing `e_shoff`) is a different operation from this one."""
    lib = _elf_so(tmp_path)
    before_bytes = lib.read_bytes()
    alloc = lief.ELF.Section.FLAGS.ALLOC
    before = lief.parse(str(lib))
    assert before.get_section(".symtab") is not None, "fixture should start unstripped"
    assert any(s.name.startswith(".debug_") for s in before.sections)

    removed = dict(elf_inject._strip_nonalloc(str(lib)))
    assert ".symtab" in removed and ".strtab" in removed
    assert any(n.startswith(".debug_") for n in removed)

    after = lief.parse(str(lib))
    leftover = [s.name for s in after.sections if s.name and not s.has(alloc)]
    assert leftover == [".shstrtab"], f"unexpected non-ALLOC sections left: {leftover}"
    assert after.header.numberof_sections > 0
    for keep in (".dynsym", ".dynstr", ".shstrtab"):
        assert after.get_section(keep) is not None, f"{keep} must survive"

    raw = lib.read_bytes()
    assert b"hidden_symbol_name" not in raw, "static symbol name should be gone"
    assert b"RODATA-MUST-SURVIVE" in raw, ".rodata must be untouched"
    assert b".debug_info" not in raw, "dropped section NAMES should go too"

    # The surviving links must still name the right sections. On this fixture the check is weak
    # by construction — a real toolchain puts every strippable section at the END of the table,
    # so the index remap is an identity and a bug in it would not show up here. The remap itself
    # is exercised by test_strip_handles_elf32_and_remaps_section_indices, which deliberately
    # drops a section that comes FIRST.
    names = [x.name for x in after.sections]
    for sec, expect in ((".dynsym", ".dynstr"), (".gnu.version", ".dynsym")):
        s = after.get_section(sec)
        if s is not None:
            assert names[s.link] == expect, \
                f"{sec}.sh_link points at {names[s.link]!r}, expected {expect!r}"

    # And the file must actually have shrunk, not merely lost its section headers.
    assert lib.stat().st_size < len(before_bytes), "strip did not compact the file"


def test_a_stripped_library_still_loads(tmp_path):
    """The one check that matters and that no amount of ELF parsing can substitute for: a real
    loader accepts the result and its exports still resolve. Host `dlopen` is not bionic — the
    §Method 3 post-mortem records glibc accepting files bionic refused — so this proves the
    surgery is sane, not that it is Android-safe. Phase 6 on a device is still required."""
    lib = _elf_so(tmp_path, native=True)
    elf_inject._strip_nonalloc(str(lib))
    # Fresh process: dlopen'ing before the strip would leave the file mapped while it is
    # truncated, and the SIGSEGV that follows is the test's fault, not the packer's.
    probe = (
        "import ctypes,sys;"
        f"l=ctypes.CDLL({str(lib)!r});"
        "l.host_marker.restype=ctypes.c_char_p;"
        "assert l.host_answer()==4242, 'wrong answer';"
        "assert l.host_marker()==b'RODATA-MUST-SURVIVE', 'wrong rodata';"
        "print('ok')"
    )
    r = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    assert r.returncode == 0 and "ok" in r.stdout, \
        f"stripped library failed to load: rc={r.returncode} {r.stderr[-400:]}"


def test_strip_is_idempotent(tmp_path):
    """Packing an already-stripped skeleton must be a no-op, not a second round of surgery on
    a file whose layout the first pass already rewrote."""
    lib = _elf_so(tmp_path)
    assert elf_inject._strip_nonalloc(str(lib))          # first pass removes things
    size = lib.stat().st_size
    assert elf_inject._strip_nonalloc(str(lib)) == []    # second finds nothing
    assert lib.stat().st_size == size


def test_strip_refuses_a_library_with_no_section_table(tmp_path):
    """Guard the guard: if the input already has no section headers, say so rather than
    producing something even less loadable."""
    lib = tmp_path / "noshdr.so"
    shutil.copyfile(FIXTURE, lib)
    buf = bytearray(lib.read_bytes())
    struct.pack_into("<Q", buf, 0x28, 0)                  # e_shoff = 0
    struct.pack_into("<H", buf, 0x3C, 0)                  # e_shnum = 0
    lib.write_bytes(buf)
    with pytest.raises(InjectError, match="no section header table"):
        elf_inject._strip_nonalloc(str(lib))


def test_emit_helper_refuses_a_tracing_skeleton(monkeypatch, tmp_path):
    """A `-DSOPK_RT_LOG` helper logs the target soname, `.text` RVA and size, and a final "OK"
    to logcat — which is the exact address and length to dump, plus confirmation the dump is
    valid. A real APK shipped that way, so refuse it by default."""
    monkeypatch.setattr(elf_inject, "helper_skeleton_path",
                        lambda abi: _marked_skeleton(tmp_path))
    _wire_thin(monkeypatch, undefined=["memcpy", "__android_log_print"])
    with pytest.raises(InjectError, match="SOPK_RT_LOG"):
        elf_inject._emit_helper("arm64-v8a", "libsopk_rt_x.so", _target_region(),
                                str(tmp_path / "helper.so"))


def test_allow_helper_log_permits_a_tracing_skeleton_but_warns_loudly(monkeypatch, tmp_path,
                                                                     capsys):
    """The escape hatch must not become the new "remember to use --release": it has to shout on
    every pack, because an unmarked opt-in is precisely the convention that already failed."""
    monkeypatch.setattr(elf_inject, "helper_skeleton_path",
                        lambda abi: _marked_skeleton(tmp_path))
    _wire_thin(monkeypatch, undefined=["__android_log_print"])
    out = tmp_path / "helper.so"
    elf_inject._emit_helper("arm64-v8a", "libsopk_rt_x.so", _target_region(), str(out),
                            allow_helper_log=True)
    assert out.exists()
    err = capsys.readouterr().err
    assert "TRACING build" in err and "DO NOT SHIP" in err


def test_emit_helper_refuses_a_skeleton_that_reexports_the_white_box(monkeypatch, tmp_path):
    """`WBC_API` visibility is baked into libwbcrypto.a's objects, so `-fvisibility=hidden`
    cannot hide it — only `--exclude-libs,ALL` can. Phase 4 checks this, but Phase 4 is a
    script the user can skip, and the skeleton is built by hand."""
    monkeypatch.setattr(elf_inject, "helper_skeleton_path",
                        lambda abi: _marked_skeleton(tmp_path))
    _wire_thin(monkeypatch)
    monkeypatch.setattr(elf_inject, "_exported_dynsyms",
                        lambda path: ["wbc_open", "wbc_unwrap_key"])
    with pytest.raises(InjectError, match="re-exports white-box symbols"):
        elf_inject._emit_helper("arm64-v8a", "libsopk_rt_x.so", _target_region(),
                                str(tmp_path / "helper.so"))


def test_emitted_helper_is_stripped_and_keeps_its_dynamic_symbols(monkeypatch, tmp_path):
    """End-to-end through `_emit_helper`: the emitted helper carries no non-ALLOC sections, and
    its dynamic symbol names are byte-identical to the skeleton's. The second half matters
    because `_undefined_dynsyms` — the guard that catches a 1.x archive — reads exactly that
    table, so a desync would silently empty the guard rather than break anything visibly."""
    skel = _marked_skeleton(tmp_path)
    monkeypatch.setattr(elf_inject, "helper_skeleton_path", lambda abi: skel)
    _wire_thin(monkeypatch)
    out = tmp_path / "helper.so"
    elf_inject._emit_helper("arm64-v8a", "libsopk_rt_x.so", _target_region(), str(out))

    alloc = lief.ELF.Section.FLAGS.ALLOC
    hlp = lief.parse(str(out))
    assert [s.name for s in hlp.sections if s.name and not s.has(alloc)] == [".shstrtab"]
    assert hlp.header.numberof_sections > 0
    assert _dynsym_names(str(out)) == _dynsym_names(str(skel))


def test_host_path_detector_finds_a_leaked_build_path():
    """The report found `/Users/<name>/src/.../libsodium-1.0.20/...` in a shipped helper. Those
    strings come from `__FILE__`/DWARF; the ones in mapped sections need the archive rebuilt
    with `-ffile-prefix-map`, so the packer can only warn — but it has to spot them first."""
    assert elf_inject._host_paths_in(
        b"\x00/Users/someone/src/whitebox-cryptography/src/sdk/wbcrypto.cpp\x00")
    assert elf_inject._host_paths_in(b"junk /home/dev/project/third_party/libsodium/x.c junk")
    assert elf_inject._host_paths_in(b"no paths here, just bytes") == []


def _synthetic_elf32(path, sections):
    """A minimal, deliberately NOT loadable ELF32 with a section table.

    The armeabi-v7a helper would be ELF32, and `_strip_nonalloc` carries a second set of
    struct offsets for that class. No 32-bit host toolchain is assumed to exist, so exercise
    those offsets directly rather than leaving the branch untested — a wrong offset here would
    silently corrupt a v7a helper. `sections` is [(name, sh_flags, payload, sh_link)], where
    `sh_link` is an index into `sections` (1-based, matching the on-disk table's leading null
    entry) or 0 for none.
    """
    EH, SH, PH = 52, 40, 32
    names = (b"\x00" + b"".join(n.encode() + b"\x00" for n, _, _, _ in sections)
             + b".shstrtab\x00")

    def name_off(n):
        return names.index(n.encode() + b"\x00")

    body, offs = bytearray(), []
    base = EH + PH
    for _, _, payload, _ in sections:
        offs.append(base + len(body))
        body += payload
    names_off = base + len(body)
    shoff = names_off + len(names)

    out = bytearray(b"\x7fELF\x01\x01\x01" + bytes(9))
    out += struct.pack("<HHIIIIIHHHHHH", 3, 40, 1, 0, EH, shoff, 0,
                       EH, PH, 1, SH, len(sections) + 2, len(sections) + 1)
    assert len(out) == EH
    out += struct.pack("<IIIIIIII", 1, 0, 0, 0, names_off, names_off, 0x5, 0x1000)  # PT_LOAD
    out += body
    out += names
    out += bytes(SH)                                            # SHN_UNDEF
    for (n, fl, payload, link), off in zip(sections, offs):
        out += struct.pack("<IIIIIIIIII", name_off(n), 1, fl, 0, off, len(payload),
                           link, 0, 1, 0)
    out += struct.pack("<IIIIIIIIII", name_off(".shstrtab"), 3, 0, 0, names_off, len(names),
                       0, 0, 1, 0)
    pathlib.Path(path).write_bytes(bytes(out))


def test_strip_handles_elf32_and_remaps_section_indices(tmp_path):
    """Two things at once, both otherwise untested.

    ELF32: the field offsets differ from ELF64 throughout (file, section and program headers),
    and armeabi-v7a would use them.

    Index remapping: `sh_link`/`sh_info` hold section INDICES, so every one shifts when earlier
    entries are removed. On a normal toolchain layout the strippable sections all sit at the END
    of the table, which makes the remap an identity and hides a bug in it — so this fixture puts
    a dropped section FIRST, before a kept `.dynsym` whose `sh_link` must follow `.dynstr` down
    by one. A stale `sh_link` would leave `.dynsym` pointing at whatever now occupies the old
    index, which no other check here would notice.
    """
    p = tmp_path / "tiny32.so"
    #                name           flags  payload             sh_link (1-based on-disk index)
    _synthetic_elf32(p, [(".comment",     0x0, b"SECRET-COMMENT",  0),   # dropped, FIRST
                         (".dynsym",      0x2, b"\x22" * 32,       3),   # -> .dynstr at index 3
                         (".dynstr",      0x2, b"\x00KEEP-ME-32\x00", 0),
                         (".debug_info",  0x0, b"SECRET-DWARF",    0)])  # dropped
    removed = dict(elf_inject._strip_nonalloc(str(p)))
    assert set(removed) == {".comment", ".debug_info"}, removed

    raw = p.read_bytes()
    assert b"SECRET-COMMENT" not in raw and b"SECRET-DWARF" not in raw
    assert b"KEEP-ME-32" in raw, "ALLOC content must survive"
    assert b".debug_info" not in raw, "dropped section names must go too"

    # The rewritten header must stay self-consistent, or nothing can parse the result.
    shoff, = struct.unpack_from("<I", raw, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", raw, 0x2E)
    assert shnum == 4, "null + .dynsym + .dynstr + .shstrtab"
    assert shoff + shnum * shentsize == len(raw), "section table must end the file"

    def sh(i):
        return struct.unpack_from("<IIIIIIIIII", raw, shoff + i * shentsize)

    strtab_off = sh(shstrndx)[4]

    def name(i):
        start = strtab_off + sh(i)[0]
        return raw[start:raw.index(b"\x00", start)].decode()

    assert [name(i) for i in range(1, shnum)] == [".dynsym", ".dynstr", ".shstrtab"]
    assert shstrndx == 3, "e_shstrndx must follow .shstrtab to its new index"
    # The remap: .dynsym's sh_link was 3, and .dynstr is now index 2.
    assert sh(1)[6] == 2, f".dynsym.sh_link is {sh(1)[6]}, expected 2 (.dynstr)"
    assert name(sh(1)[6]) == ".dynstr"


# ---- the v3 shared provider: its guards invert the helper's ---------------------------

def _fake_pack(blob_extra=64):
    """A PackKey with a plausible blob (>= WHITEN_SPAN, so the whitening key can be derived) but
    no real white-box — these tests exercise emit_provider's guards, not the crypto."""
    from sopack.provision import PackKey
    blob = os.urandom(cipher.WHITEN_SPAN + blob_extra)
    return PackKey(kek=os.urandom(16), blob=blob,
                   wpass=cipher.whiten_pass(b"passphrase", blob))


def test_emit_provider_refuses_a_wrong_soname(monkeypatch, tmp_path):
    """The single most dangerous new coupling. Each thin helper's DT_NEEDED string is whatever
    the LINKER recorded as the provider's DT_SONAME, so the packer cannot correct a wrong one —
    it can only refuse. Without -Wl,-soname, lld records the file PATH it was handed, which
    produces an APK that cannot load."""
    prov = _marked_provider(tmp_path, soname="sopk_wb_arm64-v8a.so")   # a path-shaped soname
    monkeypatch.setattr(elf_inject, "provider_skeleton_path", lambda abi: prov)
    # Patched unconditionally rather than via _wire_provider, which keys off the very soname
    # this test deliberately gets wrong — otherwise the export check fires first and the
    # assertion below would pass for the wrong reason.
    monkeypatch.setattr(elf_inject, "_exported_dynsyms", lambda path: [PROVIDER_ENTRY])
    with pytest.raises(InjectError, match="-Wl,-soname"):
        elf_inject.emit_provider("arm64-v8a", _fake_pack(), str(tmp_path / "p.so"))


def test_emit_provider_refuses_a_skeleton_without_the_provider_marker(monkeypatch, tmp_path):
    """The two markers differ on purpose: a provider carrying the HELPER's marker means the two
    artifacts were built from mismatched sources, which one shared marker could not detect."""
    wrong = tmp_path / "wrong_marker.so"
    b = lief.parse(FIXTURE)
    elf_inject._set_soname(b, PROVIDER_SONAME)
    b.write(str(wrong))
    with open(wrong, "ab") as f:
        f.write(HELPER_BUILD_MARKER)          # the THIN helper's marker, not the provider's
    monkeypatch.setattr(elf_inject, "provider_skeleton_path", lambda abi: wrong)
    with pytest.raises(InjectError, match="build marker"):
        elf_inject.emit_provider("arm64-v8a", _fake_pack(), str(tmp_path / "p.so"))


def test_emit_provider_refuses_a_provider_that_exports_nothing(monkeypatch, tmp_path):
    """The expectation INVERTS for this artifact: a thin helper must export nothing, the provider
    must export exactly sopk_wb_k. Zero exports means --exclude-libs,ALL or a `{ local: *; };`
    version script swallowed the entry, and no thin helper could then resolve against it."""
    prov = _marked_provider(tmp_path)
    monkeypatch.setattr(elf_inject, "provider_skeleton_path", lambda abi: prov)
    monkeypatch.setattr(elf_inject, "_exported_dynsyms", lambda path: [])
    with pytest.raises(InjectError, match="does not export"):
        elf_inject.emit_provider("arm64-v8a", _fake_pack(), str(tmp_path / "p.so"))


def test_emit_provider_refuses_leftover_wbc_imports(monkeypatch, tmp_path):
    """The pre-3.0.0-archive trap lives on the PROVIDER now, since it is the only artifact that
    links libwbcrypto.a. wbc_blob_kdf_tier in particular is the 3.0.0-only symbol."""
    prov = _marked_provider(tmp_path)
    monkeypatch.setattr(elf_inject, "provider_skeleton_path", lambda abi: prov)
    _wire_provider(monkeypatch)
    monkeypatch.setattr(elf_inject, "_undefined_dynsyms",
                        lambda path: ["memcpy", "wbc_blob_kdf_tier"])
    with pytest.raises(InjectError, match="pre-3.0.0 libwbcrypto.a"):
        elf_inject.emit_provider("arm64-v8a", _fake_pack(), str(tmp_path / "p.so"))


def test_emitted_provider_keeps_its_soname_and_region(monkeypatch, tmp_path):
    """The happy path: emit_provider must NOT rename the artifact (unlike _emit_helper, which
    renames per target), and the region must round-trip as a PROVIDER region."""
    prov = _marked_provider(tmp_path)
    monkeypatch.setattr(elf_inject, "provider_skeleton_path", lambda abi: prov)
    _wire_provider(monkeypatch)
    pack = _fake_pack()
    out = tmp_path / "emitted_provider.so"
    elf_inject.emit_provider("arm64-v8a", pack, str(out))

    assert elf_inject._dynamic_soname(lief.parse(str(out))) == PROVIDER_SONAME
    w = WbRegion.unpack(_extract_region(str(out), WB_REGION_MAGIC))
    assert (w.blob, w.wpass) == (pack.blob, pack.wpass)
    # the long-term key must never reach a shipped artifact
    assert pack.kek not in open(out, "rb").read()
    # and a target-region read must refuse it rather than parse garbage
    with pytest.raises(InjectError, match="could not find a region"):
        _extract_region(str(out))
