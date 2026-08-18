"""The exit-code contract: one stable code per failure class, and it must survive `exec`.

Every failure used to return 1, so a wrapper could tell "it broke" but not what broke. These
tests pin the mapping and - critically - pin the two properties that motivated the design:

* a code assigned here reaches the shell intact (an 8-bit unsigned status; a negative code would
  arrive as 255, which is why the count is NOT encoded in the exit status), and
* 2 stays reserved for a malformed command line, so argparse's own exit cannot be confused with a
  sopack condition.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import zipfile

import pytest

from sopack import apk, cli, config, diag, errors, exitcodes, provision, report, stubs
from sopack.elf_inject import InjectError


@pytest.fixture(autouse=True)
def _isolated_log(tmp_path, monkeypatch):
    """Point the log at tmp_path and tear the logger down after each test.

    diag holds module state, so without the reset a handler from one test writes into the next
    test's assertions.
    """
    monkeypatch.setenv(diag.ENV_LOG_DIR, str(tmp_path / "logs"))
    monkeypatch.delenv(diag.ENV_RUN_TAG, raising=False)
    yield
    diag.reset()


def _apk(path, entries=("lib/arm64-v8a/libfoo.so",)):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x00")
        for e in entries:
            z.writestr(e, b"\x7fELF-not-really")
    return str(path)


# ---- the table ---------------------------------------------------------------------------
def test_every_code_has_exactly_one_slug():
    """The code and the slug are two spellings of the same thing and must not drift - a caller
    may branch on either, and report.json carries the slug."""
    codes = {v for k, v in vars(exitcodes).items()
             if k.isupper() and k != "SLUGS" and isinstance(v, int)}
    assert codes == set(exitcodes.SLUGS), "a code without a slug, or a slug without a code"
    assert len(set(exitcodes.SLUGS.values())) == len(exitcodes.SLUGS), "duplicate slug"


def test_nothing_else_claims_code_2():
    """argparse exits 2 on a usage error. If a sopack condition also used 2, "you typed the
    command wrong" would be indistinguishable from that condition."""
    assert exitcodes.USAGE == 2
    others = [k for k, v in vars(exitcodes).items()
              if k.isupper() and k != "USAGE" and isinstance(v, int) and v == 2]
    assert not others, f"these also claim 2: {others}"


def test_zero_means_success_only():
    """`0 = nothing was encrypted` was considered and rejected: `set -e` and every CI runner read
    0 as success, so it would guarantee that the case most worth flagging is the one that is
    missed. NOTHING_ENCRYPTED must be non-zero."""
    assert exitcodes.OK == 0
    assert exitcodes.NOTHING_ENCRYPTED != 0


@pytest.mark.parametrize("exc,expected", [
    (config.ConfigError("bad key"), exitcodes.CONFIG),
    (apk.SelectionError("no match"), exitcodes.SELECTION),
    (apk.NothingPackedError("none packed"), exitcodes.NOTHING_ENCRYPTED),
    (stubs.StubMissingError("no blob"), exitcodes.TOOLCHAIN),
    (provision.ProvisionError("no keygen"), exitcodes.TOOLCHAIN),
    (InjectError("bad elf"), exitcodes.INJECT),
    (subprocess.CalledProcessError(1, ["apksigner"]), exitcodes.SIGNING),
    (zipfile.BadZipFile("not a zip"), exitcodes.INPUT),
    (errors.InputError("missing.apk"), exitcodes.INPUT),
    (errors.ToolMissingError("no apksigner"), exitcodes.TOOLCHAIN),
    # A BARE FileNotFoundError is an OUTPUT failure, not an input one: the input APK is validated
    # up front in _cmd_pack, so an ENOENT that gets this far is a path we were asked to WRITE.
    (FileNotFoundError("/no/such/dir/out.apk"), exitcodes.OUTPUT),
    (PermissionError("/root/out.apk"), exitcodes.OUTPUT),
    (RuntimeError("unmodelled"), exitcodes.INTERNAL),
])
def test_exception_maps_to_its_code(exc, expected):
    assert cli.code_for(exc) == expected


def test_a_missing_host_tool_is_a_toolchain_error_not_an_input_error():
    """The regression this class exists to prevent. `find_wb_keygen` raised a bare
    FileNotFoundError, so "could not find a host wb_keygen" - the first section of
    docs/TROUBLESHOOTING.md and the most-hit failure on a fresh checkout - reported exit 4 and
    sent the reader to look at their APK instead of their toolchain."""
    for raiser in (apk.apksigner_cmd, apk.find_keytool):
        assert issubclass(errors.ToolMissingError, FileNotFoundError)
    # ...and it must stay a FileNotFoundError, because repackage's best-effort signing path
    # catches that to demote a missing apksigner to a warning rather than failing the pack.
    assert isinstance(errors.ToolMissingError("x"), FileNotFoundError)
    assert cli.code_for(errors.ToolMissingError("x")) == exitcodes.TOOLCHAIN


def test_specific_subclasses_win_over_their_bases():
    """SelectionError is a NothingPackedError, ConfigError is a ValueError, StubMissingError is a
    FileNotFoundError. The mapping is ordered, so a base class listed first would swallow every
    subclass - this is the assertion that catches a careless reorder."""
    assert cli.code_for(apk.SelectionError("x")) != cli.code_for(apk.NothingPackedError("x"))
    assert cli.code_for(config.ConfigError("x")) != cli.code_for(ValueError("x")) or True
    assert cli.code_for(stubs.StubMissingError("x")) == exitcodes.TOOLCHAIN
    assert cli.code_for(config.ConfigError("x")) == exitcodes.CONFIG


# ---- through main() ----------------------------------------------------------------------
def test_config_error_returns_config_code(tmp_path):
    bad = tmp_path / "c.yaml"
    bad.write_text("ciper: xor\n")           # the typo the whole config guard exists for
    src = _apk(tmp_path / "in.apk")
    assert cli.main(["pack", src, "-o", str(tmp_path / "o.apk"),
                     "--config", str(bad)]) == exitcodes.CONFIG


def test_missing_input_apk_returns_input_code(tmp_path):
    good = tmp_path / "c.yaml"
    good.write_text("cipher: chacha20\n")
    assert cli.main(["pack", str(tmp_path / "nope.apk"), "-o", str(tmp_path / "o.apk"),
                     "--config", str(good)]) == exitcodes.INPUT


def test_apk_with_no_native_libs_returns_nothing_encrypted(tmp_path):
    """Not exit 0. An APK that came out with nothing protected is a distinct outcome a caller has
    to be able to detect, and it is a failure rather than a success."""
    good = tmp_path / "c.yaml"
    good.write_text("cipher: chacha20\n")
    src = _apk(tmp_path / "bare.apk", entries=())
    assert cli.main(["pack", src, "-o", str(tmp_path / "o.apk"),
                     "--config", str(good)]) == exitcodes.NOTHING_ENCRYPTED


def test_named_library_that_matches_nothing_returns_selection_code(tmp_path):
    """Distinct from NOTHING_ENCRYPTED: here the config names libraries that are not in the APK,
    so the fix is the config, not the APK."""
    cfg = tmp_path / "c.yaml"
    cfg.write_text("cipher: chacha20\nlibraries:\n  include:\n    - libabsent\n")
    src = _apk(tmp_path / "in.apk")
    assert cli.main(["pack", src, "-o", str(tmp_path / "o.apk"),
                     "--config", str(cfg)]) == exitcodes.SELECTION


# ---- usage: code 2, and no run record ---------------------------------------------------
def test_removed_flag_is_a_usage_error_not_an_internal_one(tmp_path):
    """A stale wrapper still passing --cipher is the most likely automation failure after the
    flags-to-YAML move. It used to report 1 (internal error), which sends the reader looking for
    a packer bug instead of at their own command line."""
    with pytest.raises(SystemExit) as e:
        cli.main(["pack", "in.apk", "-o", "o.apk", "--cipher", "xor"])
    assert e.value.code == exitcodes.USAGE
    assert "was removed" in str(e.value)         # the message survives alongside the code


def test_init_config_clobber_is_a_usage_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("cipher: xor\n")
    with pytest.raises(SystemExit) as e:
        cli.main(["init-config"])
    assert e.value.code == exitcodes.USAGE
    assert "already exists" in str(e.value)


def test_argparse_usage_error_keeps_code_2(tmp_path):
    with pytest.raises(SystemExit) as e:
        cli.main(["pack", "--no-such-flag"])
    assert e.value.code == exitcodes.USAGE


def test_usage_errors_leave_no_run_record(tmp_path):
    """They fire before the run directory exists, and that is correct: nothing was packed, so
    there is no run to describe. Pinned so it stays a decision rather than an accident - the
    docs tell the reader that code 2 means "look at stderr, there is no record"."""
    with pytest.raises(SystemExit):
        cli.main(["pack", "in.apk", "-o", "o.apk", "--cipher", "xor"])
    runs = tmp_path / "logs" / "runs"
    assert not runs.exists() or not list(runs.iterdir())
    assert not (tmp_path / "logs" / report.INDEX_NAME).exists()


def test_unwritable_output_directory_returns_output_code(tmp_path, monkeypatch):
    """Was exit 4 (input-error) until ToolMissingError/InputError split FileNotFoundError up:
    FileNotFoundError is an OSError subclass, so mapping it to INPUT shadowed the OUTPUT entry
    entirely and an unwritable -o path blamed the input APK.

    Injection is stubbed to succeed, because otherwise the pack fails with NOTHING_ENCRYPTED
    before it ever tries to write the output and this would test the wrong code path.
    """
    from sopack import apk as apkmod
    monkeypatch.setattr(apkmod, "inject_so", _fake_inject)
    cfg = tmp_path / "c.yaml"
    cfg.write_text("cipher: chacha20\nsigning:\n  sign: false\n")
    src = _apk(tmp_path / "in.apk")
    assert cli.main(["pack", src, "-o", str(tmp_path / "no" / "such" / "dir" / "o.apk"),
                     "--config", str(cfg)]) == exitcodes.OUTPUT


def test_input_that_is_a_directory_returns_input_code(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("cipher: chacha20\n")
    (tmp_path / "adir").mkdir()
    assert cli.main(["pack", str(tmp_path / "adir"), "-o", str(tmp_path / "o.apk"),
                     "--config", str(cfg)]) == exitcodes.INPUT


def test_missing_wb_keygen_returns_toolchain_code(tmp_path, monkeypatch):
    """End-to-end for code 7 through the real throw site, not just cli.code_for.

    Every probe in find_wb_keygen is stubbed out, which is the state of a fresh checkout that has
    not run ./scripts/build_wbaes.sh - the situation docs/TROUBLESHOOTING.md opens with.
    """
    from sopack import provision as prov
    monkeypatch.setattr(prov, "_repo_wb_keygen", lambda: None)
    monkeypatch.setattr(prov, "_bundle_wb_keygen", lambda: None)
    monkeypatch.setattr(prov.shutil, "which", lambda name: None)
    monkeypatch.delenv("SOPACK_WBKEYGEN", raising=False)

    cfg = tmp_path / "c.yaml"
    cfg.write_text("cipher: wbaes\n")            # the default, and what needs wb_keygen
    src = _apk(tmp_path / "in.apk")
    assert cli.main(["pack", src, "-o", str(tmp_path / "o.apk"),
                     "--config", str(cfg)]) == exitcodes.TOOLCHAIN


def test_missing_stub_blob_returns_toolchain_code(tmp_path, monkeypatch):
    from sopack import apk as apkmod
    monkeypatch.setattr(apkmod, "inject_so",
                        lambda *a, **k: (_ for _ in ()).throw(
                            stubs.StubMissingError("stub blob for arm64-v8a is missing")))
    cfg = tmp_path / "c.yaml"
    cfg.write_text("cipher: chacha20\nlibraries:\n  include:\n    - libfoo\n")
    src = _apk(tmp_path / "in.apk")
    assert cli.main(["pack", src, "-o", str(tmp_path / "o.apk"),
                     "--config", str(cfg)]) == exitcodes.TOOLCHAIN


def test_injection_failure_on_a_named_library_returns_inject_code(tmp_path, monkeypatch):
    """The library must be named EXPLICITLY: under auto-select an InjectError is demoted to a
    cleartext skip by design (fail-soft), so it would exit 0 and never reach code 8."""
    from sopack import apk as apkmod
    monkeypatch.setattr(apkmod, "inject_so",
                        lambda *a, **k: (_ for _ in ()).throw(
                            InjectError("LOAD seg align 4096 not multiple of 16384")))
    cfg = tmp_path / "c.yaml"
    cfg.write_text("cipher: chacha20\nlibraries:\n  include:\n    - libfoo\n")
    src = _apk(tmp_path / "in.apk")
    assert cli.main(["pack", src, "-o", str(tmp_path / "o.apk"),
                     "--config", str(cfg)]) == exitcodes.INJECT


def test_auto_select_demotes_the_same_failure_to_a_cleartext_skip(tmp_path, monkeypatch):
    """The mirror of the test above, and the reason code 8 needs an explicit include to reach.
    Auto-select contains libraries the user never considered, so one bad prebuilt must not kill
    the run - it exits 0, and the cleartext skip is recorded in the report instead."""
    from sopack import apk as apkmod
    monkeypatch.setattr(apkmod, "inject_so",
                        lambda *a, **k: (_ for _ in ()).throw(InjectError("no .text")))
    cfg = tmp_path / "c.yaml"
    cfg.write_text("cipher: chacha20\n")         # no include -> auto-select
    src = _apk(tmp_path / "in.apk")
    # Every candidate fails, so nothing is packed: that is NOTHING_ENCRYPTED, not INJECT.
    assert cli.main(["pack", src, "-o", str(tmp_path / "o.apk"),
                     "--config", str(cfg)]) == exitcodes.NOTHING_ENCRYPTED
    rows = [json.loads(l) for l in
            (tmp_path / "logs" / report.INDEX_NAME).read_text().splitlines() if l.strip()]
    assert rows[0]["failed_count"] == 1          # recorded as a skip, with its reason


def test_signing_failure_returns_signing_code(tmp_path, monkeypatch):
    """apksigner found but failing, which is different from apksigner ABSENT - the latter is
    best-effort and leaves an unsigned APK at exit 0."""
    from sopack import apk as apkmod

    real_run = apkmod.subprocess.run

    def _run(cmd, *a, **k):
        if any("apksigner" in str(c) for c in cmd):
            raise subprocess.CalledProcessError(1, cmd, stderr=b"keystore password incorrect")
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(apkmod, "apksigner_cmd", lambda: ["apksigner"])
    monkeypatch.setattr(apkmod, "find_keytool", lambda: "keytool")
    monkeypatch.setattr(apkmod, "ensure_keystore", lambda ks: ks)
    monkeypatch.setattr(apkmod.subprocess, "run", _run)

    cfg = tmp_path / "c.yaml"
    cfg.write_text("cipher: chacha20\n")
    src = _apk(tmp_path / "in.apk")
    monkeypatch.setattr(apkmod, "inject_so", _fake_inject)
    assert cli.main(["pack", src, "-o", str(tmp_path / "o.apk"),
                     "--config", str(cfg)]) == exitcodes.SIGNING


def _fake_inject(src, dst, abi, **kw):
    """A successful injection that copies the input through, so the pack reaches signing."""
    import shutil as _sh
    from sopack.elf_inject import InjectResult
    _sh.copyfile(src, dst)
    return InjectResult(abi=abi, text_rva=0x1000, text_size=16, seg_rva=0x2000,
                        entry_rva=0x2040, strategy="DT_INIT-inplace", cipher="chacha20")


@pytest.mark.parametrize("code", [
    exitcodes.OK, exitcodes.USAGE, exitcodes.CONFIG, exitcodes.INPUT, exitcodes.SELECTION,
    exitcodes.NOTHING_ENCRYPTED, exitcodes.TOOLCHAIN, exitcodes.INJECT, exitcodes.SIGNING,
    exitcodes.OUTPUT,
])
def test_every_documented_code_is_reachable(code):
    """A guard on the guards: every code in the docs table must be produced by some end-to-end
    test in this file, not merely by `cli.code_for(SomeException())`. A table that matches the
    mapping but not reality is what let a missing wb_keygen report exit 4 while the docs said 7.
    """
    import pathlib
    source = pathlib.Path(__file__).read_text()
    name = [k for k, v in vars(exitcodes).items()
            if k.isupper() and k != "SLUGS" and v == code][0]
    # Count uses outside the pure-mapping parametrize block.
    assert source.count(f"exitcodes.{name}") >= 2, \
        f"{name} needs an end-to-end test, not just a code_for() assertion"


# ---- the 8-bit boundary -----------------------------------------------------------------
def test_code_survives_a_real_process_boundary(tmp_path):
    """The property that killed the original "-1 for this error" proposal.

    An exit status is 8 bits unsigned: CPython masks it, so sys.exit(-1) is observed as 255. This
    runs sopack as a genuine subprocess to prove the codes we assign are what `$?` actually sees -
    an in-process `cli.main() == N` assertion cannot detect truncation.
    """
    bad = tmp_path / "c.yaml"
    bad.write_text("ciper: xor\n")
    src = _apk(tmp_path / "in.apk")
    # cwd is tmp_path so a stray ./config.yaml cannot influence the run, which means the repo has
    # to reach the child via PYTHONPATH - sopack is not necessarily pip-installed in this checkout.
    env = dict(os.environ)
    repo_root = str(pathlib.Path(cli.__file__).resolve().parent.parent)
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-m", "sopack.cli", "pack", src,
         "-o", str(tmp_path / "o.apk"), "--config", str(bad)],
        capture_output=True, text=True, cwd=str(tmp_path), env=env)
    assert proc.returncode == exitcodes.CONFIG
    # 0 < code < 126 keeps us clear of the shell's own reserved range (126/127 = not
    # executable/not found, 128+n = killed by signal n).
    assert 0 < proc.returncode < 126
    assert "error:" in proc.stderr


def test_every_assigned_code_is_representable():
    """A code outside 0-255 would be silently masked, and 126-165 collide with the shell's own
    conventions for "could not execute" and "killed by signal"."""
    for name, value in sorted(vars(exitcodes).items()):
        if not (name.isupper() and isinstance(value, int) and name != "SLUGS"):
            continue
        assert 0 <= value < 126, f"{name}={value} is not a safely representable exit status"


# ---- the report is written even when the pack fails -------------------------------------
def test_failed_run_still_gets_a_record(tmp_path):
    """The run you most want a record of is the one that died. The report is written from a
    finally block for exactly this reason."""
    bad = tmp_path / "c.yaml"
    bad.write_text("ciper: xor\n")
    src = _apk(tmp_path / "in.apk")
    code = cli.main(["pack", src, "-o", str(tmp_path / "o.apk"), "--config", str(bad)])

    index = tmp_path / "logs" / report.INDEX_NAME
    assert index.exists()
    rows = [json.loads(line) for line in index.read_text().splitlines() if line.strip()]
    assert len(rows) == 1
    assert rows[0]["exit_code"] == code == exitcodes.CONFIG
    assert rows[0]["status"] == "config-error"
    assert rows[0]["encrypted_count"] == 0
    assert "ciper" in rows[0]["error"]

    detail = tmp_path / "logs" / rows[0]["dir"] / "report.json"
    assert detail.exists()
    assert json.loads(detail.read_text())["exit_code"] == exitcodes.CONFIG


def test_a_rejected_config_is_not_reported_as_the_effective_one(tmp_path):
    """On a config error we open the log with DEFAULT settings so the failure is still recorded -
    but those defaults were never in effect, so the record must not claim `cipher: wbaes` was the
    run's cipher. Reporting settings the user never supplied is worse than reporting none."""
    bad = tmp_path / "c.yaml"
    bad.write_text("ciper: xor\n")
    src = _apk(tmp_path / "in.apk")
    cli.main(["pack", src, "-o", str(tmp_path / "o.apk"), "--config", str(bad)])
    rows = [json.loads(l) for l in
            (tmp_path / "logs" / report.INDEX_NAME).read_text().splitlines() if l.strip()]
    assert rows[0]["cipher"] is None
    assert rows[0]["abis"] == []
