"""Library selection: auto-select, exclusion patterns, the `abis:` default, fail-soft skips.

These cover the selection layer only - they never build a real ELF. The end-to-end tests
that do live in test_integration.py / test_wbaes.py.
"""
from __future__ import annotations

import shutil
import zipfile

import pytest

from sopack import apk, cli, config
from sopack.apk import (ALWAYS_EXCLUDE_PATTERNS, _classify, _match_lib_pattern,
                        build_excludes)
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


@pytest.mark.parametrize("spelling", [
    "libapp", "libapp.so", "lib/arm64-v8a/libapp.so", "libap*",
])
def test_include_matches_exactly_like_exclude(spelling):
    """`include` and `exclude` sit two lines apart in the config, so they MUST accept the
    same spellings. `include: [libapp]` used to match nothing (exact set membership) while
    `exclude: [libflutter]` worked - the pack then aborted with "no .so entries matched",
    which names the list but not the reason."""
    assert _explicit("libapp.so", [spelling])[0] is True


@pytest.mark.parametrize("so", ["libapp2.so", "libappx.so", "libotherapp.so"])
def test_a_bare_include_name_is_not_a_prefix_match(so):
    """The optional-.so rule must not turn `libapp` into `libapp*` - that would silently
    pack neighbours the user never named, which for an explicit list is the whole point."""
    assert _explicit(so, ["libapp"])[0] is False


def test_exclusion_still_beats_an_include_glob():
    """Widening `include` must not become a way around the enforced patterns."""
    ex = build_excludes()
    assert _explicit("libsopk_wb.so", ["libsopk*"], ex)[0] is False
    assert _explicit("libsopk_wb.so", ["*"], ex)[0] is False


# ---- 3-5. exclusion ---------------------------------------------------------------
def test_sopack_artifacts_are_never_selected():
    """The provider and thin helpers must never be fed back through inject_so.

    The `[]` case is the one that matters now that the exclusion list is user-editable
    YAML: `libraries.exclude: []` is a VALID config (unlike `include: []`), and it is
    exactly the shape a user reaches for when they want to pack everything. It must still
    be impossible to select sopack's own decryptor - build_excludes prepends
    ALWAYS_EXCLUDE_PATTERNS whatever the caller passes.
    """
    for so in ("libsopk_wb.so", "libsopk_rt_libapp.so"):
        for ex in (build_excludes(), build_excludes([]), build_excludes(["libfoo"])):
            assert _auto(so, ex)[0] is False
            # ... not even when named explicitly.
            assert _explicit(so, [so], ex)[0] is False


def test_exclusion_beats_explicit_lib():
    ex = build_excludes(["libapp"])
    assert _explicit("libapp.so", ["libapp.so"], ex) == (False, "excluded by 'libapp'")


def test_a_pattern_applies_to_both_modes():
    # Passed literally rather than sourced from the config layer: this module tests the
    # selection layer on its own. That the shipped default still CONTAINS libflutter is a
    # config-layer fact, pinned in test_config.py.
    ex = build_excludes(["libflutter"])
    assert _auto("libflutter.so", ex) == (False, "excluded by 'libflutter'")
    assert _explicit("libflutter.so", ["libflutter.so"], ex)[0] is False


def test_build_excludes_always_prepends_the_enforced_patterns():
    """Enforced in code, not merely written in the shipped config - so a hand-written
    config that omits them is still safe."""
    assert build_excludes() == ALWAYS_EXCLUDE_PATTERNS
    assert build_excludes([]) == ALWAYS_EXCLUDE_PATTERNS
    assert build_excludes(["a", "b"]) == ALWAYS_EXCLUDE_PATTERNS + ("a", "b")


def test_build_excludes_deduplicates():
    """Every generated config lists the enforced patterns, so they arrive twice. Without
    the de-dupe the CLI's `excluding:` line names each of them twice, which reads as a bug."""
    ex = build_excludes(list(ALWAYS_EXCLUDE_PATTERNS) + ["libflutter"])
    assert ex == ALWAYS_EXCLUDE_PATTERNS + ("libflutter",)
    assert len(ex) == len(set(ex))


# ---- 6. CLI plumbing --------------------------------------------------------------
# Everything except the input and output APK moved into the YAML config; the parsing and
# validation assertions that used to live here are in test_config.py now. What is left is
# the CLI surface itself: what argv still accepts, and what it must refuse.
def test_pack_surface_is_input_output_and_config_only():
    """The whole point of the config file. A new flag added here is a regression."""
    args = cli.build_parser().parse_args(
        ["pack", "in.apk", "-o", "out.apk", "--config", "c.yaml"])
    assert (args.input, args.output, args.config) == ("in.apk", "out.apk", "c.yaml")
    assert vars(args).keys() == {"cmd", "input", "output", "config", "func"}


@pytest.mark.parametrize("flag,key", sorted(cli._REMOVED_FLAGS.items()))
def test_removed_flags_fail_loudly_and_name_their_config_key(flag, key, capsys):
    """A stale flag in a script must FAIL, not be silently accepted and ignored.

    The whole surface moved at once, so argparse's bare "unrecognized arguments: --cipher"
    would leave the reader to guess the key. Each message names its replacement.
    """
    with pytest.raises(SystemExit) as e:
        cli.main(["pack", "in.apk", "-o", "out.apk", flag, "x"])
    assert key in str(e.value)
    # Also caught when glued on with `=`, which argparse accepts for long options.
    with pytest.raises(SystemExit):
        cli.main(["pack", "in.apk", "-o", "out.apk", f"{flag}=x"])


def test_wb_keygen_is_neither_a_flag_nor_a_config_key():
    """Removed, not deprecated: provision.find_wb_keygen probes vendor/wbc/bin/ and the
    portable bundle itself, so there is nothing left to point at. It did not come back as a
    config key either - a key would re-open "where does it rank?" against that probe order,
    in which $SOPACK_WBKEYGEN deliberately ranks BELOW a freshly gated local build."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(
            ["pack", "in.apk", "-o", "out.apk", "--wb-keygen", "/some/wb_keygen"])
    with pytest.raises(config.ConfigError, match="unknown key"):
        config.loads("wb-keygen: /some/wb_keygen\n")


def test_init_config_writes_a_file_that_parses_to_the_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["init-config"]) == 0
    written = tmp_path / "config.yaml"
    assert written.read_text() == config.SAMPLE_YAML
    assert config.loads(written.read_text()) == config.Config.default()


def test_init_config_refuses_to_clobber(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("cipher: xor\n")
    with pytest.raises(SystemExit, match="already exists"):
        cli.main(["init-config"])
    assert (tmp_path / "config.yaml").read_text() == "cipher: xor\n"


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
        "lib/arm64-v8a/libflutter.so",      # excluded by the caller's list
        "lib/arm64-v8a/libsopk_wb.so",      # excluded unconditionally, list or no list
        "lib/x86_64/libapp.so",             # outside the default abis
    ])
    with pytest.raises(RuntimeError, match="none of the 3 lib/<abi>/"):
        apk.repackage(src, str(tmp_path / "out.apk"), None,
                      exclude_libs=["libflutter"], logger=lambda *_: None)


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
    # exclude_libs is explicit: libflutter is a CONFIG-layer default now, so a direct
    # repackage() call knows nothing about it. Only ALWAYS_EXCLUDE_PATTERNS is implicit here.
    res = apk.repackage(src, str(tmp_path / "out.apk"), None, keystore=ks, min_sdk=24,
                        exclude_libs=["libflutter"], logger=lambda *_: None)

    assert len(res.injected) == 1
    assert dict(res.untouched) == {
        "lib/arm64-v8a/libflutter.so": "excluded by 'libflutter'",
        "lib/armeabi-v7a/libapp.so": "abi not selected",
    }
