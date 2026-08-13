"""Library selection: auto-select, exclusion patterns, --abi default, fail-soft skips.

These cover the selection layer only - they never build a real ELF. The end-to-end tests
that do live in test_integration.py / test_wbaes.py.
"""
from __future__ import annotations

import shutil
import zipfile

import pytest

from sopack import apk, cli
from sopack.apk import (ALWAYS_EXCLUDE_PATTERNS, DEFAULT_EXCLUDE_PATTERNS,
                        _classify, _match_lib_pattern, build_excludes)
from sopack.elf_inject import InjectError, InjectResult
from sopack.stubs import DEFAULT_ABIS, SUPPORTED_ABIS

ARM64 = {"arm64-v8a"}


def _auto(so, excludes=(), abis=ARM64, abi="arm64-v8a"):
    return _classify(f"lib/{abi}/{so}", abi, so, None, abis, excludes)


def _explicit(so, wanted, excludes=(), abis=ARM64, abi="arm64-v8a"):
    return _classify(f"lib/{abi}/{so}", abi, so, set(wanted), abis, excludes)


# ---- 1. pattern matching ----------------------------------------------------------
@pytest.mark.parametrize("pat,so,hit", [
    ("libsopk_*", "libsopk_wb.so", True),
    ("libsopk_*", "libsopk_rt_libapp.so", True),
    ("libsopk_*", "libsopkx.so", False),
    ("libflutter", "libflutter.so", True),      # .so suffix is optional in the pattern
    ("libflutter", "libflutterx.so", False),    # ... but it is not a prefix match
    ("libflutter.so", "libflutter.so", True),
    ("libmy*", "libmyfoo.so", True),
    ("libmy*", "libotherfoo.so", False),
])
def test_match_lib_pattern(pat, so, hit):
    assert _match_lib_pattern(f"lib/arm64-v8a/{so}", so, pat) is hit


def test_match_lib_pattern_full_path():
    entry, so = "lib/arm64-v8a/libfoo.so", "libfoo.so"
    assert _match_lib_pattern(entry, so, "lib/arm64-v8a/*")
    assert not _match_lib_pattern(entry, so, "lib/x86_64/*")


# ---- 2. auto-select ---------------------------------------------------------------
def test_auto_select_takes_everything_in_selected_abis():
    for so in ("libapp.so", "libc++_shared.so", "libweird-name.so"):
        assert _auto(so) == (True, "")


def test_auto_select_respects_abi_filter():
    # armeabi-v7a is merely outside the default --abi ...
    assert _auto("libapp.so", abis=set(DEFAULT_ABIS),
                 abi="armeabi-v7a") == (False, "abi not selected")
    assert _auto("libapp.so", abis=set(SUPPORTED_ABIS), abi="armeabi-v7a") == (True, "")
    # ... but lib/x86/ can never be packed, so the reason must not imply --abi would help.
    for abis in (set(DEFAULT_ABIS), set(SUPPORTED_ABIS)):
        assert _auto("libapp.so", abis=abis, abi="x86") == (
            False, "abi not supported by sopack")


def test_explicit_selection_still_matches_basename_or_full_path():
    assert _explicit("libapp.so", ["libapp.so"]) == (True, "")
    assert _explicit("libapp.so", ["lib/arm64-v8a/libapp.so"]) == (True, "")
    assert _explicit("libapp.so", ["libother.so"]) == (False, "not requested")


# ---- 3-5. exclusion ---------------------------------------------------------------
def test_sopack_artifacts_are_never_selected():
    """The provider and thin helpers must never be fed back through inject_so."""
    for so in ("libsopk_wb.so", "libsopk_rt_libapp.so"):
        for ex in (build_excludes(), build_excludes(no_default_exclude=True)):
            assert _auto(so, ex)[0] is False
            # ... not even when named explicitly.
            assert _explicit(so, [so], ex)[0] is False


def test_exclusion_beats_explicit_lib():
    ex = build_excludes(["libapp"])
    assert _explicit("libapp.so", ["libapp.so"], ex) == (False, "excluded by 'libapp'")


def test_default_exclude_applies_to_both_modes():
    ex = build_excludes()
    assert _auto("libflutter.so", ex) == (False, "excluded by 'libflutter'")
    assert _explicit("libflutter.so", ["libflutter.so"], ex)[0] is False


def test_no_default_exclude_re_enables_libflutter_only():
    ex = build_excludes(no_default_exclude=True)
    assert ex == ALWAYS_EXCLUDE_PATTERNS
    assert _auto("libflutter.so", ex) == (True, "")
    assert _auto("libsopk_wb.so", ex)[0] is False


def test_build_excludes_order_and_content():
    assert build_excludes() == ALWAYS_EXCLUDE_PATTERNS + DEFAULT_EXCLUDE_PATTERNS
    assert build_excludes(["a", "b"]) == (ALWAYS_EXCLUDE_PATTERNS
                                          + DEFAULT_EXCLUDE_PATTERNS + ("a", "b"))


# ---- 6. CLI plumbing --------------------------------------------------------------
def test_split_list_handles_repeats_commas_and_blanks():
    assert cli._split_list(["a.so, b.so", "", "c.so ,, d.so"]) == \
        ["a.so", "b.so", "c.so", "d.so"]
    assert cli._split_list(None) == []
    assert cli._split_list([" , "]) == []


def _abis(argv):
    args = cli.build_parser().parse_args(["pack", "in.apk", "-o", "out.apk"] + argv)
    if args.abi == "all":
        return SUPPORTED_ABIS
    return tuple(args.abi.split(",")) if args.abi else DEFAULT_ABIS


def test_abi_default_is_arm64_only():
    assert DEFAULT_ABIS == ("arm64-v8a",)
    assert _abis([]) == DEFAULT_ABIS
    assert _abis(["--abi", "all"]) == SUPPORTED_ABIS
    assert _abis(["--abi", "arm64-v8a,x86_64"]) == ("arm64-v8a", "x86_64")


def test_unsupported_abi_still_rejected():
    args = cli.build_parser().parse_args(
        ["pack", "in.apk", "-o", "out.apk", "--abi", "mips"])
    with pytest.raises(SystemExit, match="unsupported ABI"):
        cli._cmd_pack(args)


def test_lib_and_libs_remain_mutually_exclusive():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(
            ["pack", "in.apk", "-o", "out.apk", "--lib", "a.so", "--libs", "l.txt"])


def test_empty_libs_file_is_an_error_not_auto_select(tmp_path):
    """`--libs empty.txt` must NOT silently widen the scope to every library."""
    f = tmp_path / "libs.txt"
    f.write_text("# only a comment\n\n")
    with pytest.raises(SystemExit, match="no libraries listed"):
        cli._read_libs(str(f))


# ---- 7. zero-library errors -------------------------------------------------------
def _mkapk(path, names):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"stub")
        for n in names:
            z.writestr(n, b"\x7fELF-not-really")
    return str(path)


def test_no_libs_at_all(tmp_path):
    src = _mkapk(tmp_path / "in.apk", [])
    out = str(tmp_path / "out.apk")
    with pytest.raises(RuntimeError, match="no lib/<abi>/\\*\\.so entries at all"):
        apk.repackage(src, out, None, logger=lambda *_: None)
    with pytest.raises(RuntimeError, match="no .so entries matched the requested list"):
        apk.repackage(src, out, ["libfoo.so"], logger=lambda *_: None)


def test_everything_excluded_or_out_of_abi(tmp_path):
    src = _mkapk(tmp_path / "in.apk", [
        "lib/arm64-v8a/libflutter.so",      # default-excluded
        "lib/arm64-v8a/libsopk_wb.so",      # always-excluded
        "lib/x86_64/libapp.so",             # outside the default --abi
    ])
    with pytest.raises(RuntimeError, match="none of the 3 lib/<abi>/"):
        apk.repackage(src, str(tmp_path / "out.apk"), None, logger=lambda *_: None)


# ---- 8. fail-soft under auto-select, hard fail when named -------------------------
_SIGNING = shutil.which("keytool") and shutil.which("apksigner")
requires_signing = pytest.mark.skipif(
    not _SIGNING, reason="needs keytool + apksigner to produce a signed APK")


def _fake_inject(failing: set[str]):
    """Stand-in for inject_so: writes a marker, or raises for the named targets."""
    def _inject(src, dst, abi, *, target_name=None, cipher="chacha20", **kw):
        if target_name in failing:
            raise InjectError(f"synthetic failure for {target_name}")
        with open(dst, "wb") as f:
            f.write(b"INJECTED")
        return InjectResult(abi=abi, text_rva=0x1000, text_size=8, seg_rva=0x2000,
                            entry_rva=0x2010, strategy="DT_INIT-hijack", cipher=cipher)
    return _inject


@requires_signing
def test_auto_select_skips_failures_and_keeps_original_bytes(tmp_path, monkeypatch):
    src = _mkapk(tmp_path / "in.apk", ["lib/arm64-v8a/libgood.so",
                                       "lib/arm64-v8a/libbad.so"])
    out = str(tmp_path / "out.apk")
    monkeypatch.setattr(apk, "inject_so", _fake_inject({"libbad.so"}))
    ks = apk.KeystoreInfo(path=str(tmp_path / "ks.jks"))

    res = apk.repackage(src, out, None, keystore=ks, min_sdk=24, logger=lambda *_: None)

    assert [ir.abi for ir in res.injected] == ["arm64-v8a"]
    assert [n for n, _ in res.failed] == ["lib/arm64-v8a/libbad.so"]
    assert "synthetic failure" in res.failed[0][1]
    with zipfile.ZipFile(out) as z:
        assert z.read("lib/arm64-v8a/libgood.so") == b"INJECTED"
        # the skipped one must ship byte-identical to the input, not truncated or dropped
        assert z.read("lib/arm64-v8a/libbad.so") == b"\x7fELF-not-really"


def test_explicitly_named_failure_still_aborts(tmp_path, monkeypatch):
    src = _mkapk(tmp_path / "in.apk", ["lib/arm64-v8a/libbad.so"])
    monkeypatch.setattr(apk, "inject_so", _fake_inject({"libbad.so"}))
    out = tmp_path / "out.apk"
    # the abort names the APK entry, not inject_so's temp copy
    with pytest.raises(InjectError, match=r"lib/arm64-v8a/libbad\.so: synthetic failure"):
        apk.repackage(src, str(out), ["libbad.so"], logger=lambda *_: None)
    assert not out.exists(), "an aborted pack must leave no partial output"


@requires_signing
def test_untouched_entries_carry_a_reason(tmp_path, monkeypatch):
    src = _mkapk(tmp_path / "in.apk", [
        "lib/arm64-v8a/libapp.so",
        "lib/arm64-v8a/libflutter.so",
        "lib/armeabi-v7a/libapp.so",
    ])
    monkeypatch.setattr(apk, "inject_so", _fake_inject(set()))
    ks = apk.KeystoreInfo(path=str(tmp_path / "ks.jks"))
    res = apk.repackage(src, str(tmp_path / "out.apk"), None, keystore=ks, min_sdk=24,
                        logger=lambda *_: None)

    assert len(res.injected) == 1
    assert dict(res.untouched) == {
        "lib/arm64-v8a/libflutter.so": "excluded by 'libflutter'",
        "lib/armeabi-v7a/libapp.so": "abi not selected",
    }
