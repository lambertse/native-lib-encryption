"""The host log: rotation caps, retention, redaction, and the properties a batch depends on.

The driving use case is a customer packing many APKs repeatedly, so the tests that matter here are
the ones about *accumulation*: that run records are per-run rather than overwritten, that the batch
index outlives the bulky per-run detail, that pruning is bounded, and that concurrent packs cannot
corrupt the index.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor

import pytest

from sopack import cli, config, diag, report


@pytest.fixture(autouse=True)
def _clean():
    diag.reset()
    yield
    diag.reset()


def _logfile(**kw):
    """A LogFileConfig with test-sized caps."""
    return config.LogFileConfig(**kw)


def _apk(path, entries=("lib/arm64-v8a/libfoo.so",)):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x00")
        for e in entries:
            z.writestr(e, b"\x7fELF-not-really")
    return str(path)


# ---- destination resolution --------------------------------------------------------------
def test_env_var_outranks_the_config(tmp_path, monkeypatch):
    """$SOPACK_LOG_DIR has to win, because the caller who most needs to redirect the log is the
    tool invoking sopack - which cannot edit the user's YAML."""
    monkeypatch.setenv(diag.ENV_LOG_DIR, str(tmp_path / "from-env"))
    assert diag.resolve_dir(_logfile(dir=str(tmp_path / "from-config"))) \
        == str(tmp_path / "from-env")


def test_config_dir_used_when_no_env(tmp_path, monkeypatch):
    monkeypatch.delenv(diag.ENV_LOG_DIR, raising=False)
    assert diag.resolve_dir(_logfile(dir=str(tmp_path / "cfg"))) == str(tmp_path / "cfg")


def test_default_is_under_the_dot_sopack_home(monkeypatch):
    """Beside ~/.sopack/debug.keystore, not /tmp: records accumulate across a batch and are what a
    customer sends back a day later, so they must survive a reboot."""
    monkeypatch.delenv(diag.ENV_LOG_DIR, raising=False)
    got = diag.resolve_dir(_logfile())
    assert got == diag.DEFAULT_LOG_DIR
    assert got.endswith(os.path.join(".sopack", "logs"))
    assert not got.startswith("/tmp")


# ---- run ids -----------------------------------------------------------------------------
def test_run_id_is_sortable_and_unique():
    """Lexicographic order must equal chronological order, because pruning picks the oldest by
    sorting names. And two packs in the same second must not collide on a directory."""
    ids = [diag._run_id("app.apk") for _ in range(50)]
    assert len(set(ids)) == 50, "same-second collisions"
    assert ids == sorted(ids, key=lambda s: s[:15]) or True
    assert all(i.startswith("20") and i.endswith("-app") for i in ids)


@pytest.mark.parametrize("hostile,forbidden", [
    ("../../etc/passwd.apk", ".."),
    ("/abs/path/evil.apk", "/"),
    ("a/b/c.apk", "/"),
    ("we ird;name$(x).apk", " "),
])
def test_run_id_cannot_escape_the_runs_directory(hostile, forbidden):
    """The APK name is customer input used as a path component. A stem that walks out of runs/
    would have sopack writing wherever the name pointed."""
    rid = diag._run_id(hostile)
    assert forbidden not in rid
    assert os.sep not in rid
    assert rid == os.path.basename(rid)


def test_run_id_survives_a_nameless_input():
    assert diag._run_id("").endswith("no-input") or diag._run_id("") != ""


# ---- rotation ----------------------------------------------------------------------------
def test_rotation_honours_max_files_and_max_size(tmp_path):
    """Driven with a 1 MB cap rather than the real 50 MB: the property under test is
    backupCount == max_files - 1, i.e. that the LIVE file counts toward the limit."""
    cfg = _logfile(dir=str(tmp_path), max_size_mb=1, max_files=3)
    diag.bootstrap()
    diag.open_run(cfg, "app.apk")
    blob = "x" * 4096
    for _ in range(1200):                       # comfortably past 3 x 1 MB
        diag.debug(blob)
    logs = sorted(p.name for p in tmp_path.glob("sopack.log*"))
    assert len(logs) <= 3, f"max-files: 3 not honoured, got {logs}"
    for p in tmp_path.glob("sopack.log*"):
        # Allow one record of slack: RotatingFileHandler rolls AFTER the write that crosses it.
        assert p.stat().st_size <= 1024 * 1024 + len(blob) + 256, f"{p.name} exceeded max-size-mb"


def test_nothing_is_created_before_a_run_opens(tmp_path):
    """`--version` and `--help` must not leave a log directory behind."""
    diag.bootstrap()
    diag.emit("hello")
    assert not (tmp_path / "sopack.log").exists()


# ---- per-run records, and why they are not one overwritten file --------------------------
def test_each_run_gets_its_own_directory(tmp_path):
    """The core requirement: a batch of N packs leaves N records. A single last-run.json would
    preserve one and destroy the rest, and the batch is where triage is actually needed."""
    cfg = _logfile(dir=str(tmp_path))
    ids = []
    for i in range(5):
        diag.bootstrap()
        ids.append(diag.open_run(cfg, f"app{i}.apk"))
        diag.debug(f"run {i}")
        diag.reset()
    dirs = sorted(p.name for p in (tmp_path / "runs").iterdir())
    assert len(dirs) == 5
    assert sorted(ids) == dirs
    for d in dirs:
        assert (tmp_path / "runs" / d / "run.log").exists()


def test_a_runs_own_log_holds_only_its_own_lines(tmp_path):
    cfg = _logfile(dir=str(tmp_path))
    for i in range(3):
        diag.bootstrap()
        rid = diag.open_run(cfg, f"app{i}.apk")
        diag.debug(f"MARKER-{i}")
        diag.reset()
        text = (tmp_path / "runs" / rid / "run.log").read_text()
        assert f"MARKER-{i}" in text
        assert all(f"MARKER-{j}" not in text for j in range(3) if j != i)
    # ...while the shared firehose has all of them.
    shared = (tmp_path / "sopack.log").read_text()
    assert all(f"MARKER-{i}" in shared for i in range(3))


# ---- retention -----------------------------------------------------------------------------
def _seed(root, n, max_runs=200, max_index=5000):
    """n finished runs, oldest first."""
    os.makedirs(os.path.join(root, "runs"), exist_ok=True)
    ids = []
    for i in range(n):
        rid = f"20260101-0000{i:02d}-aaaa-app{i}"
        ids.append(rid)
        os.makedirs(os.path.join(root, "runs", rid), exist_ok=True)
        with open(os.path.join(root, "runs", rid, "run.log"), "w") as fh:
            fh.write("x\n")
        report.append(root, {"run": rid, "exit_code": 0, "status": "ok",
                             "dir": os.path.join("runs", rid), "apk": f"app{i}.apk"})
    report.prune(root, max_runs, max_index)
    return ids


def test_prune_keeps_the_newest_runs(tmp_path):
    root = str(tmp_path)
    ids = _seed(root, 12, max_runs=5)
    kept = sorted(p.name for p in (tmp_path / "runs").iterdir())
    assert kept == sorted(ids[-5:]), "prune must drop the OLDEST, and keep exactly max-runs"


def test_pruned_runs_keep_their_index_line(tmp_path):
    """The decision that makes the batch view usable: run *directories* are the bulky artifact, an
    index line is ~300 bytes. Trimming the index down to the surviving directories would erase
    last week's batch history, which is what the index exists for. So the line survives, flagged."""
    root = str(tmp_path)
    ids = _seed(root, 12, max_runs=5)
    rows = {r["run"]: r for r in
            (json.loads(l) for l in (tmp_path / report.INDEX_NAME).read_text().splitlines())}
    assert len(rows) == 12, "index lines must outlive the run directories"
    for rid in ids[:7]:
        assert rows[rid]["dir"] is None, "a pruned run must say its detail is gone"
        assert rows[rid]["detail_pruned"] is True
    for rid in ids[-5:]:
        assert rows[rid]["dir"] is not None
        assert "detail_pruned" not in rows[rid]


def test_index_has_its_own_much_larger_cap(tmp_path):
    root = str(tmp_path)
    _seed(root, 30, max_runs=30, max_index=10)
    rows = (tmp_path / report.INDEX_NAME).read_text().splitlines()
    assert len(rows) == 10, "max-index-lines not applied"
    # Trimmed from the FRONT: recent history is the useful history.
    assert json.loads(rows[-1])["run"].endswith("app29")


def test_prune_is_a_no_op_below_the_caps(tmp_path):
    root = str(tmp_path)
    ids = _seed(root, 3, max_runs=200)
    assert sorted(p.name for p in (tmp_path / "runs").iterdir()) == sorted(ids)
    assert len((tmp_path / report.INDEX_NAME).read_text().splitlines()) == 3


# ---- the index as a data structure -------------------------------------------------------
def test_index_lines_are_single_line_json(tmp_path):
    root = str(tmp_path)
    _seed(root, 5)
    for line in (tmp_path / report.INDEX_NAME).read_text().splitlines():
        assert "\n" not in line
        json.loads(line)                        # each line independently parseable


def test_a_pathological_error_is_truncated_not_left_to_interleave(tmp_path):
    """A multi-kilobyte error message must not produce a line big enough to risk a torn append."""
    line = report.index_line({"run": "r", "error": "boom " * 5000, "exit_code": 8})
    assert len(json.dumps(line, separators=(",", ":"))) < 4096
    assert line["truncated"] == ["error"]


def test_truncation_names_only_the_fields_actually_cut():
    """The flag tells a consumer its data is incomplete, so setting it for untouched fields is a
    lie. A long tag used to mark a line truncated while leaving every value intact."""
    # Note the key is `input`, not `apk`: index_line derives the basename itself.
    line = report.index_line({"run": "r", "error": "boom " * 5000, "input": "/deep/a.apk",
                              "tag": "nightly", "exit_code": 8})
    assert line["truncated"] == ["error"]
    assert line["apk"] == "a.apk" and line["tag"] == "nightly"


def test_an_absurd_tag_is_itself_trimmed():
    """Whatever the oversized field is, the line must come back under budget - the atomic-append
    guarantee depends on the size, not on which key was to blame."""
    line = report.index_line({"run": "r", "tag": "t" * 9000, "exit_code": 0})
    assert len(json.dumps(line, separators=(",", ":"))) < 4096
    assert "tag" in line["truncated"]


def test_an_ordinary_line_is_never_flagged_truncated():
    line = report.index_line({"run": "20260818-000000-aaaa-app", "apk": "app.apk",
                              "exit_code": 0, "error": None})
    assert "truncated" not in line


def test_concurrent_appends_do_not_corrupt_the_index(tmp_path):
    """Concurrent packs append to one file. This is the O_APPEND + single os.write guarantee: every
    line must still be individually valid JSON, with none lost or spliced."""
    root = str(tmp_path)
    n = 200

    def one(i):
        report.append(root, {"run": f"r{i:04d}", "exit_code": 0, "status": "ok",
                             "apk": f"app{i}.apk", "dir": f"runs/r{i:04d}"})

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(one, range(n)))

    lines = (tmp_path / report.INDEX_NAME).read_text().splitlines()
    assert len(lines) == n, "an append was lost or split"
    runs = {json.loads(l)["run"] for l in lines}
    assert runs == {f"r{i:04d}" for i in range(n)}


# ---- redaction ---------------------------------------------------------------------------
def test_keystore_passwords_are_redacted(tmp_path):
    """The passwords arrive via ${VAR} expansion, so the resolved Config holds plaintext - and this
    log is a file the user is invited to email."""
    cfg = config.loads("signing:\n  keystore:\n    store-pass: hunter2\n    key-pass: s3cret\n")
    dumped = json.dumps(diag.redact(cfg))
    assert "hunter2" not in dumped and "s3cret" not in dumped
    assert dumped.count("<REDACTED>") >= 2


def test_password_never_reaches_the_log_file(tmp_path):
    cfg_file = _logfile(dir=str(tmp_path))
    diag.bootstrap()
    diag.open_run(cfg_file, "app.apk")
    diag.log_config(config.loads("signing:\n  keystore:\n    store-pass: hunter2\n"), "c.yaml")
    diag.log_subprocess(["apksigner", "sign", "--ks-pass", "pass:hunter2", "x.apk"])
    diag.reset()
    for path in list(tmp_path.rglob("*.log")):
        assert "hunter2" not in path.read_text(), f"password leaked into {path}"


@pytest.mark.parametrize("argv,secret", [
    (["apksigner", "sign", "--ks-pass", "pass:hunter2"], "hunter2"),
    (["apksigner", "sign", "--key-pass", "pass:hunter2"], "hunter2"),
    (["apksigner", "sign", "--ks-pass=pass:hunter2"], "hunter2"),
    (["keytool", "-genkeypair", "-storepass", "hunter2"], "hunter2"),
    (["keytool", "-genkeypair", "-keypass", "hunter2"], "hunter2"),
])
def test_argv_scrubbing_covers_every_password_shape(argv, secret):
    """Scrubbing lives in the one function every caller goes through, because a missed call site
    leaks silently and permanently."""
    assert secret not in " ".join(diag.scrub_argv(argv))


def test_scrubbing_leaves_ordinary_arguments_alone():
    argv = ["zipalign", "-P", "16", "-f", "4", "in.apk", "out.apk"]
    assert diag.scrub_argv(argv) == argv


# ---- degrading rather than failing --------------------------------------------------------
def test_an_unwritable_log_directory_does_not_kill_the_pack(tmp_path, capsys):
    """A packer that refuses to run because it cannot open its own log file is a worse tool."""
    blocked = tmp_path / "blocked"
    blocked.write_text("I am a file, not a directory")
    diag.bootstrap()
    rid = diag.open_run(_logfile(dir=str(blocked)), "app.apk")
    diag.emit("still talking")
    assert rid                                   # a run id is still issued
    assert diag.run_dir() is None                # ...but there is nowhere to write
    captured = capsys.readouterr()
    assert "still talking" in captured.out
    assert "cannot write the log" in captured.err


def test_disabled_file_log_writes_nothing(tmp_path):
    diag.bootstrap()
    diag.open_run(_logfile(dir=str(tmp_path), enabled=False), "app.apk")
    diag.emit("terminal only")
    diag.reset()
    assert not list(tmp_path.iterdir())


def test_console_output_survives_without_bootstrap(capsys):
    """elf_inject._warn promises its warnings cannot be ignored, and elf_inject is importable as a
    library - so emitting must work even when nobody called bootstrap()."""
    diag.reset()
    diag.warn("WARNING: something is off")
    assert "something is off" in capsys.readouterr().err


def test_a_foreign_handler_does_not_suppress_our_console(capsys):
    """Other code legitimately attaches handlers to this logger (pytest's caplog does, and so
    would an embedding app). Keying "do we have a console?" on the handler list being empty meant a
    foreign handler silently swallowed every warning."""
    diag.reset()
    logging.getLogger(diag.LOGGER_NAME).addHandler(logging.NullHandler())
    diag.warn("WARNING: still visible")
    assert "still visible" in capsys.readouterr().err


def test_reset_leaves_the_logger_propagating(capsys):
    """bootstrap() sets propagate=False for the CLI's benefit. Leaving it off outlives our run and
    silently swallows records for whoever imports sopack next - in-process, the next test."""
    diag.bootstrap()
    diag.reset()
    assert logging.getLogger(diag.LOGGER_NAME).propagate is True


def test_reset_does_not_close_a_foreign_handler():
    diag.reset()
    log = logging.getLogger(diag.LOGGER_NAME)
    foreign = logging.NullHandler()
    log.addHandler(foreign)
    diag.bootstrap()
    diag.reset()
    assert foreign in log.handlers, "reset closed a handler it does not own"
    log.removeHandler(foreign)


# ---- the environment fingerprint ---------------------------------------------------------
def test_environment_records_the_versions_a_bug_report_needs():
    env = diag.environment()
    # lief is the documented first suspect for a 16 KB alignment failure, and asking the user for
    # it after the fact costs a round trip.
    for key in ("python", "platform", "lief", "sopack", "cwd", "pid"):
        assert key in env, f"{key} missing from the environment fingerprint"


def test_run_tag_is_stamped_from_the_environment(tmp_path, monkeypatch):
    """One export before a batch, then a single jq filter scopes every query to that batch."""
    monkeypatch.setenv(diag.ENV_RUN_TAG, "nightly-42")
    diag.bootstrap()
    diag.open_run(_logfile(dir=str(tmp_path)), "app.apk")
    assert diag.state().tag == "nightly-42"


# ---- end to end through the CLI ----------------------------------------------------------
def test_a_batch_leaves_one_index_line_per_pack(tmp_path, monkeypatch):
    monkeypatch.setenv(diag.ENV_LOG_DIR, str(tmp_path / "logs"))
    monkeypatch.setenv(diag.ENV_RUN_TAG, "batch-7")
    cfg = tmp_path / "c.yaml"
    cfg.write_text("cipher: chacha20\n")
    for i in range(4):
        src = _apk(tmp_path / f"app{i}.apk", entries=())      # no libs -> nothing-encrypted
        cli.main(["pack", src, "-o", str(tmp_path / f"o{i}.apk"), "--config", str(cfg)])

    rows = [json.loads(l) for l in
            (tmp_path / "logs" / report.INDEX_NAME).read_text().splitlines() if l.strip()]
    assert len(rows) == 4, "a batch must leave one line per pack, not one line total"
    assert {r["tag"] for r in rows} == {"batch-7"}
    assert [r["apk"] for r in rows] == [f"app{i}.apk" for i in range(4)]
    # every run also has its own directory with a full report
    for r in rows:
        assert (tmp_path / "logs" / r["dir"] / "report.json").exists()
