"""The run record's shape: what a caller is allowed to depend on.

`report.json` and `index.jsonl` are a published interface the moment another tool reads them, so
these tests pin the keys, the schema version, and the split between the two files - counts and
scalars in the index line, per-library arrays only in the full report.
"""
from __future__ import annotations

import json

import pytest

from sopack import config, exitcodes, report
from sopack.apk import RepackResult
from sopack.elf_inject import InjectResult


def _ir(entry="lib/arm64-v8a/libapp.so", abi="arm64-v8a"):
    return InjectResult(abi=abi, text_rva=0x1000, text_size=4096, seg_rva=0x9000,
                        entry_rva=0x9040, strategy="DT_INIT-inplace", cipher="chacha20",
                        entry=entry)


def _built(res, code=exitcodes.OK, error=None, cfg=None):
    return report.build(cfg or config.Config.default(), res,
                        input_apk="in.apk", output_apk="out.apk", exit_code=code,
                        error=error, config_source="./config.yaml", run="20260818-000000-aaaa-in",
                        started_iso="2026-08-18T00:00:00Z", duration_ms=1234)


# ---- the documented keys -----------------------------------------------------------------
_REQUIRED = {
    "schema", "run", "tag", "started", "duration_ms", "exit_code", "status", "input", "output",
    "config_source", "container", "cipher", "abis", "encrypted_count", "failed_count",
    "not_selected_count", "signed", "encrypted", "failed", "not_selected", "per_abi", "warnings",
    "environment", "error", "log", "config",
}


def test_report_carries_every_documented_key():
    got = _built(RepackResult(injected=[_ir()], output="out.apk"))
    assert _REQUIRED <= set(got), f"missing: {_REQUIRED - set(got)}"
    assert got["schema"] == report.SCHEMA == 1


def test_report_is_json_serialisable():
    """It is written with json.dump, so a non-serialisable value would fail AFTER the pack
    succeeded - the worst possible time."""
    got = _built(RepackResult(injected=[_ir()], failed=[("lib/x/y.so", "boom")],
                              untouched=[("lib/z/w.so", "abi not selected")]))
    json.loads(json.dumps(got, default=str))


def test_status_slug_matches_the_exit_code():
    for code in report.exitcodes.SLUGS:
        got = _built(RepackResult(), code=code)
        assert got["status"] == exitcodes.slug(code)


# ---- counts -------------------------------------------------------------------------------
def test_counts_and_per_abi_agree_with_the_lists():
    res = RepackResult(
        injected=[_ir("lib/arm64-v8a/a.so"), _ir("lib/arm64-v8a/b.so")],
        failed=[("lib/arm64-v8a/c.so", "align"), ("lib/x86_64/d.so", "align")],
        untouched=[("lib/armeabi-v7a/e.so", "abi not selected")],
        output="out.apk")
    got = _built(res)
    assert got["encrypted_count"] == 2 == len(got["encrypted"])
    assert got["failed_count"] == 2 == len(got["failed"])
    assert got["not_selected_count"] == 1 == len(got["not_selected"])
    assert got["per_abi"]["arm64-v8a"] == {"encrypted": 2, "failed": 1, "not_selected": 0}
    assert got["per_abi"]["x86_64"] == {"encrypted": 0, "failed": 1, "not_selected": 0}
    assert got["per_abi"]["armeabi-v7a"] == {"encrypted": 0, "failed": 0, "not_selected": 1}


def test_encrypted_entries_name_the_library_and_how_it_was_hijacked():
    """`entry` is why InjectResult gained a field: inject_so only ever sees a temp copy, so
    without it the report could not say WHICH library it encrypted."""
    got = _built(RepackResult(injected=[_ir()], output="out.apk"))
    one = got["encrypted"][0]
    assert one["entry"] == "lib/arm64-v8a/libapp.so"
    assert one["strategy"] == "DT_INIT-inplace"
    assert one["text_size"] == 4096
    assert one["cipher"] == "chacha20"


def test_a_run_that_never_reached_repackage_still_builds_a_record():
    """res=None is the config-error case, and it must produce a usable record rather than raise -
    a batch triages from these, so the failed run is the one that most needs a line."""
    got = _built(None, code=exitcodes.CONFIG, error="ciper: unknown key")
    assert got["encrypted_count"] == 0
    assert got["encrypted"] == []
    assert got["status"] == "config-error"
    assert got["error"] == "ciper: unknown key"


def test_signed_is_none_when_signing_was_never_reached():
    """None, not False: "we never got that far" and "deliberately left unsigned" are different
    facts, and a caller checking `signed is False` should not be told a failed pack was unsigned."""
    assert _built(None, code=exitcodes.CONFIG)["signed"] is None
    assert _built(RepackResult(signed=False))["signed"] is False
    assert _built(RepackResult(signed=True))["signed"] is True


# ---- the index line -----------------------------------------------------------------------
def test_index_line_carries_counts_but_not_the_arrays():
    """Keeping the line small is what keeps its append atomic against a concurrent pack. The
    per-library detail belongs in report.json, which nothing else is writing to."""
    full = _built(RepackResult(injected=[_ir() for _ in range(50)],
                               failed=[(f"lib/a/{i}.so", "x") for i in range(50)]))
    line = report.index_line(full)
    assert line["encrypted_count"] == 50
    assert line["failed_count"] == 50
    for absent in ("encrypted", "failed", "not_selected", "per_abi", "environment", "config"):
        assert absent not in line, f"{absent} must not bloat the index line"
    assert len(json.dumps(line, separators=(",", ":"))) < 4096


def test_index_line_points_at_its_run_directory():
    line = report.index_line(_built(RepackResult(injected=[_ir()])))
    assert line["dir"] == "runs/20260818-000000-aaaa-in"
    assert line["run"] == "20260818-000000-aaaa-in"


def test_index_line_summarises_warnings_by_count():
    """A degraded exit-0 run - libraries in cleartext, an unsigned output - has to be visible in
    the batch view, otherwise a clean pack and a mostly-failed pack look identical."""
    full = report.build(config.Config.default(), RepackResult(injected=[_ir()]),
                        input_apk="in.apk", output_apk="out.apk", exit_code=exitcodes.OK,
                        error=None, config_source=None, run="r", warnings=["a", "b"])
    assert report.index_line(full)["warning_count"] == 2


def test_apk_names_in_the_index_are_basenames():
    """A full path would blow the line budget on a deep CI checkout, and the basename is what a
    human reads in the triage output anyway."""
    line = report.index_line(_built(RepackResult(injected=[_ir()])))
    assert "/" not in (line["apk"] or "")


# ---- round trip through the file ---------------------------------------------------------
def test_append_then_read_back(tmp_path):
    root = str(tmp_path)
    for i in range(3):
        report.append(root, {"run": f"r{i}", "exit_code": i, "status": "ok"})
    rows = [json.loads(l) for l in (tmp_path / report.INDEX_NAME).read_text().splitlines()]
    assert [r["run"] for r in rows] == ["r0", "r1", "r2"]
    assert [r["exit_code"] for r in rows] == [0, 1, 2]


def test_append_creates_the_file_with_restrictive_permissions(tmp_path):
    """The record embeds paths and environment details, so it should not be world-readable by
    default even though the passwords themselves are redacted."""
    root = str(tmp_path)
    report.append(root, {"run": "r"})
    mode = (tmp_path / report.INDEX_NAME).stat().st_mode & 0o777
    assert mode & 0o077 == 0, f"index.jsonl is group/world accessible ({oct(mode)})"


def test_config_in_the_report_is_redacted(tmp_path):
    cfg = config.loads("signing:\n  keystore:\n    store-pass: hunter2\n")
    got = _built(RepackResult(), cfg=cfg)
    assert "hunter2" not in json.dumps(got, default=str)
    assert got["config"]["signing"]["keystore"]["store-pass"] == "<REDACTED>"
