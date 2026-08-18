"""Host-side diagnostics: the terminal output, the rotating log, and the per-run record.

Why this module is called `diag` and not `log`
----------------------------------------------
`apk.repackage()` has a parameter named `log` (the on-device stub-log boolean). A module named
`log` would be shadowed by it inside that function body, so `log.debug(...)` there would resolve
to a bool and raise AttributeError on every call. `repackage`'s signature is library API that
the tests call directly, so the module took the different name instead of the parameter.

What this replaces
------------------
Every diagnostic used to be a bare `print()`, which meant a failure on a customer's machine left
nothing to inspect: the scrollback was gone, and the details that actually explain a failure
(resolved config, which wb_keygen was picked, lief's version, apksigner's stderr, the traceback)
were never printed at all because the terminal output is deliberately terse.

The layout, and why there are two views
---------------------------------------
    <dir>/sopack.log[.1-.N]   rotating firehose, every run interleaved, run-id + pid tagged
    <dir>/index.jsonl         ONE COMPACT LINE PER RUN, append-only: the batch view
    <dir>/.lock               flock target for pruning and index trimming
    <dir>/runs/<run-id>/      report.json + run.log - one self-contained record per pack

They do different jobs. `sopack.log` is a chronological firehose with a hard byte cap;
`runs/<id>/` is the unit you attach to a bug report, and a run's log and its report are created
and pruned TOGETHER so they can never disagree. The driving use case is a *batch* - customers
pack many APKs repeatedly - which is why a single overwritten `last-run.json` would be useless:
40 packs would preserve one record and destroy 39, and a batch is exactly where "three of these
failed and I don't know which" happens.

Invariants worth keeping
------------------------
* **The terminal output is byte-for-byte what it was before this module existed.** The console
  handler emits `record.getMessage()` with no level prefix and no timestamp, INFO to stdout and
  WARNING+ to stderr, mirroring the previous `print()` / `print(file=sys.stderr)` split. A test
  diffs the two streams separately against master.
* **Logging must never break a pack.** Every filesystem operation here is best-effort: an
  unwritable log directory degrades to console-only with one warning. A packer that refuses to
  run because it cannot open its own log file is a worse tool than one that just does not log.
* **The destination comes from the config, but a config error is what most needs logging.** So
  `bootstrap()` installs the console handler plus an in-memory buffer, and `open_run()` flushes
  that buffer into the files once the destination is known. A ConfigError still gets a complete
  run directory, at the default location.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import platform
import re
import shutil
import sys
import time
from dataclasses import fields, is_dataclass

LOGGER_NAME = "sopack"

# Beside ~/.sopack/debug.keystore (apk.DEFAULT_KEYSTORE_PATH). Not /tmp: run records accumulate
# across a batch and are the thing a customer sends back a day later, so they must survive a
# reboot, and /tmp is world-writable on a shared host.
DEFAULT_LOG_DIR = os.path.join(os.path.expanduser("~"), ".sopack", "logs")

# Outranks the config, so a caller that cannot edit the YAML - the tool invoking sopack, a CI
# job - can still redirect the log. Ranked the other way round it would be useless for exactly
# the case it exists for.
ENV_LOG_DIR = "SOPACK_LOG_DIR"

# Stamped into every record. A batch wrapper exports it once and then one jq filter scopes every
# query to that batch: jq 'select(.tag=="nightly-42")' index.jsonl
ENV_RUN_TAG = "SOPACK_RUN_TAG"

_LEVELS = {"debug": logging.DEBUG, "info": logging.INFO,
           "warning": logging.WARNING, "error": logging.ERROR}

# Anything whose dataclass field name matches gets REDACTED in the config dump and the report.
# The keystore passwords arrive via ${VAR} expansion, so the resolved Config holds plaintext and
# a verbatim dump would write a real password into a file the user is about to email.
_SECRET_FIELDS = re.compile(r"pass|secret|token|key_pass", re.I)
_REDACTED = "<REDACTED>"

# A run id must be safe as a single path component: the APK stem comes from customer input, so
# "../../etc/passwd.apk" must not escape runs/.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
_STEM_MAX = 40


class _Run:
    """The mutable per-run state. One instance at a time; `_run` below holds it."""

    def __init__(self, run_id: str, root: str, run_dir: str | None, cfg_file) -> None:
        self.id = run_id
        self.root = root
        self.dir = run_dir              # None when the filesystem refused us
        self.cfg = cfg_file
        self.started = time.time()
        self.started_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.started))
        self.tag = os.environ.get(ENV_RUN_TAG) or None
        self.warnings: list[str] = []


_run: _Run | None = None
_buffer: logging.handlers.MemoryHandler | None = None
_file_handlers: list[logging.Handler] = []


# ---- terminal handlers -------------------------------------------------------------------
class _VerbatimFormatter(logging.Formatter):
    """The message and nothing else - no level, no timestamp, no logger name.

    This is what keeps the terminal identical to the previous `print()` calls. Do not "improve"
    it with a level prefix: the CLI's output is a designed report (see cli._print_summary), and
    prefixing every line with INFO would wreck its indentation-carried structure.
    """

    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


class _StdStreamHandler(logging.StreamHandler):
    """A StreamHandler that resolves `sys.stdout`/`sys.stderr` at EMIT time, not construction.

    A plain StreamHandler captures the stream object once and keeps writing to it forever. That
    breaks anything which replaces the stream afterwards - pytest's capsys, and any embedder that
    redirects output - because the handler goes on writing into whatever stream existed when the
    handler was built. The symptom is warnings silently vanishing, which is exactly what
    `elf_inject._warn` exists to prevent, so this is a correctness fix rather than test plumbing.
    """

    def __init__(self, which: str) -> None:
        self._which = which
        super().__init__(getattr(sys, which))

    @property
    def stream(self):
        return getattr(sys, self._which)

    @stream.setter
    def stream(self, value) -> None:
        # StreamHandler.__init__ and setStream() both assign here; the property above is the
        # single source of truth, so the assignment is deliberately dropped.
        pass


class _MaxLevel(logging.Filter):
    """Keep records at or below `level` - the stdout half of the stream split."""

    def __init__(self, level: int) -> None:
        super().__init__()
        self.level = level

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno <= self.level


def logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def _console_handlers() -> list[logging.Handler]:
    """INFO -> stdout, WARNING+ -> stderr.

    Mirrors the old `print()` / `print(file=sys.stderr)` split, which callers redirect separately -
    scripts/device_test.sh greps `^error: ` out of a combined capture, and the harness would break
    if warnings moved streams.
    """
    out = _StdStreamHandler("stdout")
    out.setLevel(logging.INFO)
    out.addFilter(_MaxLevel(logging.INFO))
    out.setFormatter(_VerbatimFormatter())

    err = _StdStreamHandler("stderr")
    err.setLevel(logging.WARNING)
    err.setFormatter(_VerbatimFormatter())
    return [_own(out), _own(err)]


# Ownership marker. Identifying our handlers by TYPE would be wrong in both directions: a foreign
# FileHandler would look like ours (and get closed), while a subclass of ours might not. Tagging
# the instances we create is unambiguous, and it matters because `bootstrap`/`reset` run inside a
# process we do not own - pytest attaches handlers to this logger, and so would an embedding app.
_OWNED = "_sopack_owned"


def _own(handler: logging.Handler) -> logging.Handler:
    setattr(handler, _OWNED, True)
    return handler


def _is_ours(handler: logging.Handler) -> bool:
    return getattr(handler, _OWNED, False)


def _drop_ours(log: logging.Logger, *, close: bool) -> None:
    for handler in list(log.handlers):
        if not _is_ours(handler):
            continue
        log.removeHandler(handler)
        if close:
            try:
                handler.close()
            except Exception:                           # pragma: no cover - defensive
                pass


def _ensure_console() -> logging.Logger:
    """Guarantee that emitting reaches a terminal even if `bootstrap()` was never called.

    This is not defensive padding - it upholds `elf_inject._warn`'s contract that its warnings
    "must survive being ignored". Those fire deep inside injection and describe an artifact that
    is not shippable, and `elf_inject`/`apk` are importable as a library: the tests call
    `_emit_helper` directly, and so can any other consumer. Without this, a logger with no
    handlers would silently discard exactly the warnings that matter most.
    """
    log = logger()
    log.setLevel(logging.DEBUG)         # handlers decide what surfaces; the logger never filters
    # Keyed on OUR handler type, not on `log.handlers` being empty. Other code legitimately
    # attaches handlers to this logger - pytest's caplog does, and so would any application
    # embedding sopack - and none of them provide the stdout/stderr split the CLI's output
    # depends on. Testing for emptiness meant a foreign handler suppressed our console output
    # entirely, which is how a "must not be ignorable" warning became invisible.
    if not any(isinstance(h, _StdStreamHandler) for h in log.handlers):
        for handler in _console_handlers():
            log.addHandler(handler)
    # Note: `propagate` is deliberately NOT touched here. Silencing a host application's own
    # logging is the CLI's call to make (bootstrap does it), not something a library-level
    # warning should impose on its caller.
    return log


def bootstrap() -> None:
    """Install the console handlers and start buffering for the file log.

    Called first thing in `cli.main`, before the config is read, so that a config error is both
    printed and (once open_run runs) recorded.
    """
    global _buffer
    log = logger()
    log.setLevel(logging.DEBUG)
    log.propagate = False
    # Only ours: a handler pytest or an embedding application attached is not ours to remove.
    _drop_ours(log, close=False)
    for handler in _console_handlers():
        log.addHandler(handler)

    # capacity is a ceiling, not a flush trigger: target=None means it never auto-flushes, and
    # flushLevel is raised above CRITICAL so an error does not dump the buffer to nowhere.
    _buffer = logging.handlers.MemoryHandler(capacity=100000, flushLevel=logging.CRITICAL + 1,
                                            target=None)
    _buffer.setLevel(logging.DEBUG)
    log.addHandler(_own(_buffer))


# ---- emitting ----------------------------------------------------------------------------
# `warning:` / `WARNING` is how this codebase has always marked a warning inside an otherwise
# ordinary progress line (apk.py's skip and unsigned notices, elf_inject._warn). Detecting it
# keeps those on stderr at WARNING without rewriting 11 call sites to pass a level.
_WARNISH = re.compile(r"\bwarning\b", re.I)


def emit(msg: str) -> None:
    """The drop-in for `print()`, and the `logger=` callable `apk.repackage` already accepts."""
    log = _ensure_console()
    log.warning(msg) if _WARNISH.search(msg) else log.info(msg)


def debug(msg: str) -> None:
    """File-only detail. Never reaches the terminal - this is where the diagnosis lives."""
    _ensure_console().debug(msg)


def warn(msg: str) -> None:
    _ensure_console().warning(msg)


def note_warning(msg: str) -> None:
    """Record a caveat in the run report AND print it.

    For conditions that leave a usable output but change what the artifact is - an unsigned APK,
    libraries that shipped in cleartext. Those are exit-0 successes, so without this they have no
    machine-readable trace at all and a batch cannot tell a clean pack from a degraded one.
    """
    if _run is not None:
        _run.warnings.append(msg)
    _ensure_console().warning(msg)


def run_warnings() -> list[str]:
    return list(_run.warnings) if _run is not None else []


# ---- run lifecycle -----------------------------------------------------------------------
def _run_id(input_apk: str) -> str:
    """`YYYYmmdd-HHMMSS-<4 hex>-<stem>`, UTC so it sorts chronologically.

    The random suffix is not decoration: concurrent packs started in the same second would
    otherwise collide on the directory name and interleave two runs' logs into one file.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    salt = os.urandom(2).hex()
    stem = os.path.basename(input_apk or "no-input")
    if stem.lower().endswith(".apk"):
        stem = stem[:-4]
    stem = _UNSAFE.sub("_", stem)[:_STEM_MAX].strip("._-") or "apk"
    return f"{stamp}-{salt}-{stem}"


def resolve_dir(cfg_file) -> str:
    """$SOPACK_LOG_DIR, else the config, else ~/.sopack/logs."""
    env = os.environ.get(ENV_LOG_DIR)
    if env:
        return os.path.expanduser(env)
    if cfg_file is not None and getattr(cfg_file, "dir", None):
        return cfg_file.dir
    return DEFAULT_LOG_DIR


def open_run(cfg_file, input_apk: str) -> str:
    """Create this run's directory, install the file handlers, flush the buffered records.

    Returns the run id. Never raises: if the log cannot be opened we warn once and carry on with
    console-only output, because failing a pack over its own logging would be absurd.
    """
    global _run
    root = resolve_dir(cfg_file)
    run_id = _run_id(input_apk)
    enabled = cfg_file is None or cfg_file.enabled

    if not enabled:
        _run = _Run(run_id, root, None, cfg_file)
        _drop_buffer()
        return run_id

    run_dir = None
    try:
        run_dir = os.path.join(root, "runs", run_id)
        os.makedirs(run_dir, exist_ok=True)
        _install_file_handlers(root, run_dir, cfg_file)
    except OSError as e:
        run_dir = None
        _drop_buffer()
        # WARNING, not silence: a user who configured a log directory and gets no log needs to
        # know why, and this is the one message that explains it.
        logger().warning(f"WARNING: cannot write the log under {root} ({e}); "
                         f"continuing with terminal output only.")

    _run = _Run(run_id, root, run_dir, cfg_file)
    if run_dir:
        _log_preamble()
    return run_id


def _install_file_handlers(root: str, run_dir: str, cfg_file) -> None:
    level = _LEVELS[getattr(cfg_file, "level", "debug")] if cfg_file else logging.DEBUG
    max_mb = getattr(cfg_file, "max_size_mb", 50) if cfg_file else 50
    max_files = getattr(cfg_file, "max_files", 5) if cfg_file else 5

    fmt = logging.Formatter(
        # The run id is what ties an interleaved line in the shared firehose back to a run dir,
        # and the pid is what separates two concurrent packs within the same second.
        fmt=f"%(asctime)s %(levelname)-7s [{_short(os.getpid())}] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    # backupCount is max_files-1 because the live file counts: max-files: 5 -> sopack.log plus
    # .1-.4. delay=True so `--version` and `--help` create nothing.
    shared = logging.handlers.RotatingFileHandler(
        os.path.join(root, "sopack.log"), maxBytes=max_mb * 1024 * 1024,
        backupCount=max(0, max_files - 1), encoding="utf-8", delay=True)
    shared.setLevel(level)
    shared.setFormatter(fmt)

    per_run = logging.FileHandler(os.path.join(run_dir, "run.log"), encoding="utf-8", delay=True)
    per_run.setLevel(level)
    per_run.setFormatter(fmt)

    log = logger()
    for handler in (shared, per_run):
        log.addHandler(_own(handler))
        _file_handlers.append(handler)

    # Replay everything bootstrap() buffered - crucially including a config error, which happens
    # before we know where the log goes.
    if _buffer is not None:
        _buffer.setTarget(_Fanout(_file_handlers))
        _buffer.flush()
        log.removeHandler(_buffer)


class _Fanout(logging.Handler):
    """Flush target that replays each buffered record into several handlers.

    MemoryHandler.setTarget takes exactly one handler, but the buffer has to reach both the
    shared log and this run's log.
    """

    def __init__(self, handlers: list[logging.Handler]) -> None:
        super().__init__(logging.DEBUG)
        self._handlers = list(handlers)

    def emit(self, record: logging.LogRecord) -> None:
        for handler in self._handlers:
            if record.levelno >= handler.level:
                handler.emit(record)


def _drop_buffer() -> None:
    """Discard buffered records when there is nowhere to put them."""
    if _buffer is not None:
        _buffer.buffer.clear()
        logger().removeHandler(_buffer)


def _short(pid: int) -> str:
    return f"pid:{pid}"


# ---- the preamble: what the file log knows that the terminal never says -------------------
def redact(obj):
    """A JSON-safe copy of a dataclass tree with secret-looking fields replaced."""
    if is_dataclass(obj) and not isinstance(obj, type):
        out = {}
        for f in fields(obj):
            value = getattr(obj, f.name)
            key = f.name.replace("_", "-")
            out[key] = _REDACTED if (_SECRET_FIELDS.search(f.name) and value is not None) \
                else redact(value)
        return out
    if isinstance(obj, dict):
        return {k: (_REDACTED if isinstance(k, str) and _SECRET_FIELDS.search(k)
                    else redact(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj


def environment() -> dict:
    """The host facts that turn a bug report into a diagnosis.

    lief's version is here because it is the documented first suspect for a 16 KB alignment
    failure (LIEF, not sopack, places the appended segments - see pyproject.toml), and asking a
    user for it after the fact costs a round trip.
    """
    env: dict = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cwd": os.getcwd(),
        "pid": os.getpid(),
    }
    try:
        from . import __version__
        env["sopack"] = __version__
    except Exception:                                   # pragma: no cover - defensive
        env["sopack"] = "?"
    try:
        import lief
        env["lief"] = getattr(lief, "__version__", "?")
    except Exception as e:
        env["lief"] = f"<import failed: {e}>"
    for name in ("apksigner", "zipalign", "keytool", "adb"):
        env[name] = shutil.which(name) or None
    for var in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "ANDROID_HOME",
                "SOPACK_WBKEYGEN", ENV_LOG_DIR, ENV_RUN_TAG):
        if os.environ.get(var):
            env[var] = os.environ[var]
    return env


def _log_preamble() -> None:
    assert _run is not None
    debug(f"=== sopack run {_run.id} ===")
    if _run.tag:
        debug(f"run tag ({ENV_RUN_TAG}): {_run.tag}")
    debug(f"argv: {sys.argv!r}")
    debug("environment: " + json.dumps(environment(), indent=2, sort_keys=True, default=str))


def log_config(cfg, source: str | None) -> None:
    """Record the fully resolved config, with passwords redacted."""
    debug(f"config source: {source or 'built-in defaults'}")
    debug("resolved config: " + json.dumps(redact(cfg), indent=2, sort_keys=True, default=str))


# Command-line shapes that carry a secret. apksigner takes `--ks-pass pass:hunter2` and keytool
# takes `-storepass hunter2`, so the argv of a perfectly ordinary signing call contains the
# keystore password - and this log is a file the user is invited to email. Scrubbing lives HERE,
# in the one function every caller goes through, rather than at each call site, because a missed
# call site leaks silently and forever.
_SECRET_ARG = re.compile(r"^(pass|file):", re.I)
_SECRET_FLAG = re.compile(r"^-{1,2}(ks-pass|key-pass|storepass|keypass|pass)$", re.I)


def scrub_argv(argv) -> list[str]:
    out: list[str] = []
    redact_next = False
    for raw in argv:
        arg = str(raw)
        if redact_next:
            out.append(_REDACTED)
            redact_next = False
            continue
        if _SECRET_FLAG.match(arg):
            out.append(arg)
            redact_next = True
            continue
        # `--ks-pass=pass:hunter2` and a bare `pass:hunter2` operand both hide the secret after a
        # prefix, so keep the prefix and drop the rest.
        if "=" in arg:
            head, tail = arg.split("=", 1)
            if _SECRET_FLAG.match(head):
                out.append(f"{head}={_REDACTED}")
                continue
            arg_check = tail
        else:
            arg_check = arg
        if _SECRET_ARG.match(arg_check):
            out.append(arg_check.split(":", 1)[0] + ":" + _REDACTED
                       if arg is arg_check else f"{arg.split('=', 1)[0]}={_REDACTED}")
            continue
        out.append(arg)
    return out


def log_subprocess(argv, returncode=None, stdout=None, stderr=None) -> None:
    """Every external command, with its output. The single highest-value thing here.

    apksigner/keytool/zipalign/wb_keygen failures currently surface as a one-line exception
    message with the tool's own explanation discarded (provision.py captures wb_keygen's stderr
    only to interpolate part of it). At DEBUG we keep all of it.

    argv is scrubbed of passwords first - see scrub_argv.
    """
    debug(f"exec: {scrub_argv(argv)!r}"
          + ("" if returncode is None else f" -> exit {returncode}"))
    for name, blob in (("stdout", stdout), ("stderr", stderr)):
        if not blob:
            continue
        if isinstance(blob, bytes):
            blob = blob.decode("utf-8", "replace")
        text = blob.strip()
        if text:
            debug(f"  {name}: " + text.replace("\n", "\n    "))


def run_id() -> str | None:
    return _run.id if _run is not None else None


def run_dir() -> str | None:
    return _run.dir if _run is not None else None


def run_log_path() -> str | None:
    return os.path.join(_run.dir, "run.log") if _run is not None and _run.dir else None


def state() -> "_Run | None":
    return _run


def close_run(exit_code: int, error: str | None, record: dict | None) -> None:
    """Write report.json, append the index line, prune. Best-effort throughout."""
    if _run is None or _run.dir is None:
        _flush()
        return
    try:
        if record is not None:
            path = os.path.join(_run.dir, "report.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(record, fh, indent=2, sort_keys=True, default=str)
                fh.write("\n")
            debug(f"wrote {path}")
    except OSError as e:
        logger().warning(f"WARNING: could not write the run report: {e}")
    _flush()


def _flush() -> None:
    for handler in _file_handlers:
        try:
            handler.flush()
        except Exception:                               # pragma: no cover - defensive
            pass


def reset() -> None:
    """Tear everything down. For tests, and for a second cli.main() call in one process.

    Only OUR handlers are removed. A handler someone else attached to this logger - pytest's
    caplog, an embedding application's - is not ours to close, and closing it would break the
    caller for the rest of the process.
    """
    global _run, _buffer
    log = logger()
    _drop_ours(log, close=True)
    # Restored, because bootstrap() set it False. Leaving a module-level logger permanently
    # non-propagating outlives our own run and silently swallows records for whoever imports
    # sopack next - in-process that is the next CLI invocation or the next test.
    log.propagate = True
    _file_handlers.clear()
    _run = None
    _buffer = None
