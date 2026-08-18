"""The machine-readable run record: `report.json` per run, plus one `index.jsonl` line.

This is the half of the result that an exit code cannot carry. A process exit status is 8 bits,
so it can say *what class* of thing happened but not "3 of 6 libraries were encrypted, and here
is why the other 3 were not" - see `sopack/exitcodes.py` for the full reasoning. Everything
quantitative lives here instead.

Two files, two jobs:

* **`runs/<id>/report.json`** - the complete record for one pack: every encrypted library with
  its .text range and hijack strategy, every skip with its reason, the per-ABI tally, the host
  environment. This is the file to attach to a bug report.
* **`index.jsonl`** - ONE COMPACT LINE PER RUN, appended. This is the batch primitive, and the
  reason the design is not a single overwritten `last-run.json`: customers pack many APKs
  repeatedly, so a single file would preserve one run and destroy the rest, and a batch is
  exactly where "three of these failed and I don't know which" happens. With this:

      jq -c 'select(.exit_code!=0)|{apk,exit_code,error}' index.jsonl
      jq -s 'group_by(.status)|map({(.[0].status):length})' index.jsonl

Everything here is derived from `apk.RepackResult` and the resolved `Config`, both of which
already carry what is needed - no extra bookkeeping is threaded through the pack.
"""
from __future__ import annotations

import json
import os
import shutil

from . import diag, exitcodes

# Bumped when the shape changes incompatibly, so a consumer can refuse a record it does not
# understand instead of silently reading a missing key as None.
SCHEMA = 1

INDEX_NAME = "index.jsonl"
LOCK_NAME = ".lock"
RUNS_DIR = "runs"

# An index line is meant to be one small atomic append. Past this we truncate the variable-length
# string fields rather than risk a partial write interleaving with a concurrent pack's line.
_MAX_LINE = 4000


def _abi_of(entry: str) -> str:
    parts = entry.split("/")
    return parts[1] if len(parts) > 2 else "?"


def build(cfg, res, *, input_apk, output_apk, exit_code, error, config_source,
          started_iso=None, duration_ms=None, run=None, tag=None, warnings=None) -> dict:
    """The full `report.json` body.

    `res` may be None: a run that failed before or during `repackage` still gets a record, and a
    record that says "config-error, nothing was packed" is exactly what a batch triage needs.
    """
    injected = list(getattr(res, "injected", []) or [])
    failed = list(getattr(res, "failed", []) or [])
    untouched = list(getattr(res, "untouched", []) or [])

    per_abi: dict[str, dict[str, int]] = {}

    def bump(abi: str, key: str) -> None:
        per_abi.setdefault(abi, {"encrypted": 0, "failed": 0, "not_selected": 0})[key] += 1

    for ir in injected:
        bump(ir.abi, "encrypted")
    for entry, _ in failed:
        bump(_abi_of(entry), "failed")
    for entry, _ in untouched:
        bump(_abi_of(entry), "not_selected")

    return {
        "schema": SCHEMA,
        "run": run,
        "tag": tag,
        "started": started_iso,
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "status": exitcodes.slug(exit_code),
        "input": os.path.abspath(input_apk) if input_apk else None,
        "output": os.path.abspath(output_apk) if output_apk else None,
        "config_source": config_source,
        "cipher": getattr(cfg, "cipher", None),
        "abis": list(getattr(cfg, "abis", ()) or ()),
        "encrypted_count": len(injected),
        "failed_count": len(failed),
        "not_selected_count": len(untouched),
        # None (not False) when we never got as far as signing, so a consumer can tell "left
        # unsigned" apart from "never reached that stage".
        "signed": getattr(res, "signed", None) if res is not None else None,
        "encrypted": [
            {"entry": ir.entry,
             "abi": ir.abi,
             "cipher": ir.cipher,
             "text_rva": ir.text_rva,
             "text_size": ir.text_size,
             "seg_rva": ir.seg_rva,
             "entry_rva": ir.entry_rva,
             "strategy": ir.strategy}
            for ir in injected
        ],
        "failed": [{"entry": e, "reason": r} for e, r in failed],
        "not_selected": [{"entry": e, "reason": r} for e, r in untouched],
        "per_abi": per_abi,
        # Caveats that leave a usable output but change what the artifact IS - an unsigned APK,
        # libraries that shipped in cleartext. Those are exit-0 successes, so without this a
        # batch cannot distinguish a clean pack from a degraded one.
        "warnings": list(warnings or ()),
        "environment": diag.environment(),
        "error": error,
        "log": os.path.join(RUNS_DIR, run, "run.log") if run else None,
        "config": diag.redact(cfg) if cfg is not None else None,
    }


def index_line(report: dict) -> dict:
    """The compact per-run line. COUNTS ONLY - the per-library arrays stay in report.json.

    Keeping this small is what makes the append atomic in practice; see `append` below.
    """
    line = {
        "run": report.get("run"),
        "tag": report.get("tag"),
        "ts": report.get("started"),
        "apk": os.path.basename(report.get("input") or "") or None,
        "output": os.path.basename(report.get("output") or "") or None,
        "exit_code": report.get("exit_code"),
        "status": report.get("status"),
        "cipher": report.get("cipher"),
        "abis": report.get("abis"),
        "encrypted_count": report.get("encrypted_count"),
        "failed_count": report.get("failed_count"),
        "not_selected_count": report.get("not_selected_count"),
        "signed": report.get("signed"),
        "warning_count": len(report.get("warnings") or ()),
        "duration_ms": report.get("duration_ms"),
        "error": report.get("error"),
        "dir": os.path.join(RUNS_DIR, report["run"]) if report.get("run") else None,
    }
    if len(json.dumps(line, separators=(",", ":"), default=str)) <= _MAX_LINE:
        return line
    # Trim the variable-length fields in descending order of how big they can get, stopping as
    # soon as the line fits, and only flag `truncated` for what was ACTUALLY cut - a long tag or
    # path used to set the flag while leaving every value intact, which tells a consumer its data
    # is incomplete when it is not.
    truncated = []
    for field, keep in (("error", 400), ("output", 120), ("apk", 120), ("tag", 120),
                        ("run", 120), ("dir", 200)):
        value = line.get(field)
        if isinstance(value, str) and len(value) > keep:
            line[field] = value[:keep] + "…"
            truncated.append(field)
        if len(json.dumps(line, separators=(",", ":"), default=str)) <= _MAX_LINE:
            break
    if truncated:
        line["truncated"] = truncated
    return line


def append(root: str, line: dict) -> None:
    """Append one line to index.jsonl atomically against concurrent packs.

    `os.open(O_APPEND)` + a SINGLE `os.write`, deliberately not `open(path, "a")`: buffered text
    I/O makes no promise about how many write() syscalls it issues, and the guarantee we depend on
    is that O_APPEND makes seek-to-end-and-write atomic with respect to other writers. (This is
    not a PIPE_BUF argument - that concerns pipes and says nothing about regular files.)
    """
    payload = (json.dumps(line, separators=(",", ":"), default=str) + "\n").encode("utf-8")
    path = os.path.join(root, INDEX_NAME)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)


class _Lock:
    """Best-effort flock around pruning. Concurrent packs would otherwise race on rmtree.

    Never fatal, and never blocks forever: if the lock cannot be taken we simply skip the prune
    this time. Retention is a housekeeping concern, so being one run late is harmless, whereas
    hanging a pack on a stale lock is not.
    """

    def __init__(self, root: str) -> None:
        self.path = os.path.join(root, LOCK_NAME)
        self.fd = None

    def __enter__(self):
        try:
            import fcntl
            self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT, 0o600)
            fcntl.flock(self.fd, fcntl.LOCK_EX)
            return True
        except (OSError, ImportError):
            self._close()
            return False

    def __exit__(self, *exc) -> None:
        try:
            if self.fd is not None:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        except (OSError, ImportError):
            pass
        self._close()

    def _close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


def prune(root: str, max_runs: int, max_index_lines: int) -> None:
    """Enforce retention. Run directories and index lines are capped SEPARATELY.

    Trimming the index down to the surviving run directories would destroy the batch history the
    index exists for: a run directory is bulky, an index line is ~300 bytes, and with "many APKs,
    many times" `max_runs` can be a single afternoon. So a pruned run keeps its line, with
    "dir": null and "detail_pruned": true, and the jq query still answers - it just says the
    detail is gone rather than pretending the run never happened.
    """
    with _Lock(root) as locked:
        if not locked:
            return
        pruned = _prune_runs(root, max_runs)
        _trim_index(root, max_index_lines, pruned)


def _prune_runs(root: str, max_runs: int) -> set[str]:
    runs_root = os.path.join(root, RUNS_DIR)
    try:
        names = sorted(d for d in os.listdir(runs_root)
                       if os.path.isdir(os.path.join(runs_root, d)))
    except OSError:
        return set()
    # The run id starts with a UTC timestamp, so lexicographic order IS chronological order.
    doomed = names[:max(0, len(names) - max_runs)]
    gone = set()
    for name in doomed:
        try:
            shutil.rmtree(os.path.join(runs_root, name))
            gone.add(name)
        except OSError:
            pass
    return gone


def _trim_index(root: str, max_lines: int, pruned: set[str]) -> None:
    path = os.path.join(root, INDEX_NAME)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    except OSError:
        return

    changed = False
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
        changed = True

    if pruned:
        out = []
        for ln in lines:
            try:
                rec = json.loads(ln)
            except ValueError:
                out.append(ln)          # keep anything we cannot parse; never lose data here
                continue
            if rec.get("run") in pruned and rec.get("dir") is not None:
                rec["dir"] = None
                rec["detail_pruned"] = True
                ln = json.dumps(rec, separators=(",", ":"), default=str)
                changed = True
            out.append(ln)
        lines = out

    if not changed:
        return
    # Rewrite via a temp file + rename so a reader never sees a half-written index. Safe under
    # the flock we already hold.
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("".join(ln + "\n" for ln in lines))
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def finalize(cfg, res, **kw) -> dict | None:
    """Build the record, write report.json, append the index line, prune. Best-effort.

    Called from `cli.main`'s finally block, so a failed pack is recorded too. Any exception here
    is swallowed with a warning: the pack's own result must not be replaced by a reporting bug.
    """
    st = diag.state()
    report = build(cfg, res, run=(st.id if st else None), tag=(st.tag if st else None),
                   started_iso=(st.started_iso if st else None),
                   warnings=diag.run_warnings(), **kw)
    if st is None or st.dir is None:
        return report
    try:
        diag.close_run(report["exit_code"], report["error"], report)
        append(st.root, index_line(report))
        f = st.cfg
        prune(st.root, getattr(f, "max_runs", 200) if f else 200,
              getattr(f, "max_index_lines", 5000) if f else 5000)
    except OSError as e:
        diag.warn(f"WARNING: could not record this run under {st.root}: {e}")
    return report
