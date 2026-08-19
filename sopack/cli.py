"""sopack command-line interface.

    sopack pack in.apk -o out.apk [--config PATH]
    sopack pack in.aab -o out.aab [--config PATH]
    sopack init-config [-o PATH]

The command line carries only the input and output file, and whether that file is an APK or an
Android App Bundle is DETECTED from its contents (`sopack/container.py`) rather than declared.
Every other setting - cipher, ABIs, library selection, keystore, signing and logging - lives in
a YAML config file. sopack reads
`--config PATH` if given (an error if it does not exist), else `./config.yaml`, else its
built-in defaults.

`sopack init-config` writes a fully commented config.yaml, every key set to its default, so
an unedited one packs exactly like a bare `sopack pack`. `config.sample.yaml` in the repo is
the same file.

Two things here exist for CALLERS rather than humans, because sopack is increasingly driven by
other tools:

* **A stable exit code per failure class** (`sopack/exitcodes.py`). Every failure used to
  collapse to 1, so a wrapper could tell "it broke" but not what broke.
* **A per-run record** (`sopack/report.py`) under the log directory, carrying the number of
  encrypted libraries and the reason for every one that was skipped. That is where counts live:
  an exit status is 8 bits and cannot carry both a class and a count.

The terminal output is unchanged by both. It goes through `diag.emit` instead of `print`, with a
formatter that emits the message verbatim, so stdout and stderr are byte-for-byte what they were.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import traceback
import zipfile
from pathlib import Path

from . import __version__, diag, exitcodes, report
from .apk import (DEFAULT_KEYSTORE_PATH, KeystoreInfo, NothingPackedError, SelectionError,
                  build_excludes, repackage, verify_signature)
from .config import DEFAULT_CONFIG_NAME, SAMPLE_YAML, Config, ConfigError, load
from .container import (APK as APK_CONTAINER, abi_of as _abi_of,
                        detect as detect_container)
from .elf_inject import InjectError
from .errors import InputError, ToolMissingError
from .provision import ProvisionError
from .stubs import SUPPORTED_ABIS, StubMissingError


class _Usage(SystemExit):
    """A malformed command line, as opposed to a malformed config or a failed pack.

    Its own type so it can carry exit code 2. Both places that raise it used to raise a bare
    `SystemExit(str)`, and `SystemExit` with a *string* argument exits **1** - so `--cipher` on a
    stale wrapper, the single most likely automation failure after the flags-to-YAML move,
    reported itself as an internal error.

    The two halves have to be separated because they conflict: `SystemExit(2)` gets the code right
    but makes Python print nothing, while `SystemExit(msg)` prints but exits 1. So the code goes
    to `SystemExit.__init__` (hence `.code == 2`), the message is kept on the instance, `__str__`
    returns it - which is also what `pytest.raises(..., match=...)` reads - and `main` prints it
    before re-raising.
    """

    def __init__(self, message: str) -> None:
        super().__init__(exitcodes.USAGE)
        self.message = message

    def __str__(self) -> str:
        return self.message


# Every flag that used to exist, mapped to what replaces it. Without this, a stale script
# dies on argparse's "unrecognized arguments: --cipher", which names the flag but not the
# config key - and the whole surface moved at once, so that is a lot of guessing.
_REMOVED_FLAGS = {
    "--lib": "libraries.include (a YAML list)",
    "--libs": "libraries.include (a YAML list; the separate libs file is gone)",
    "--exclude-lib": "libraries.exclude (a YAML list)",
    "--no-default-exclude": ("libraries.exclude (the built-in list it toggled is gone - "
                             "every excluded pattern is written out there now)"),
    "--cipher": "cipher:",
    "--abi": "abis: (a YAML list, or the string \"all\")",
    "--min-sdk": "signing.min-sdk:",
    "--log": "logging.stub-log: true",
    "--allow-helper-log": "logging.allow-helper-log: true",
    "--keystore": "signing.keystore.path:",
    "--ks-alias": "signing.keystore.alias:",
    "--ks-pass": "signing.keystore.store-pass:",
    "--key-pass": "signing.keystore.key-pass:",
    "--verify": "signing.verify: true (already the default)",
    "--no-verify": "signing.verify: false",
    "--no-sign": "signing.sign: false",
}


# The options that consume the NEXT argv word. A removed flag's name appearing there is a
# filename, not a flag - `--config --cipher.yaml` must report the missing file, not "--cipher
# was removed".
_TAKES_A_VALUE = ("--config", "-o", "--output")


def _reject_removed_flags(argv) -> None:
    prev = None
    for arg in argv:
        if arg == "--":                     # everything after is positional by convention
            break
        if prev in _TAKES_A_VALUE:
            prev = arg
            continue
        flag = arg.split("=", 1)[0]
        replacement = _REMOVED_FLAGS.get(flag)
        if replacement:
            raise _Usage(
                f"error: {flag} was removed - sopack is configured by a YAML file now.\n"
                f"       Set `{replacement}` in {DEFAULT_CONFIG_NAME} instead.\n"
                f"       Run `sopack init-config` to write a commented one.")
        prev = arg


def _print_summary(res, abis) -> None:
    """Per-ABI account of what got protected and what shipped in cleartext.

    A bare "Injected N libraries" reads as "the app is protected". Only arm64-v8a is
    protected in practice, so every library left in cleartext has to be visible here -
    with the reason - rather than silently dropped from the report.
    """
    if res.failed:
        diag.emit("\nSkipped (selected but could not be injected - these ship in CLEARTEXT):")
        for entry, err in res.failed:
            diag.emit(f"  {entry}: {err}")
    if res.untouched:
        by_reason: dict[str, list[str]] = {}
        for entry, reason in res.untouched:
            by_reason.setdefault(reason, []).append(entry)
        diag.emit("\nNot selected:")
        for reason in sorted(by_reason):
            names = by_reason[reason]
            diag.emit(f"  {reason}: {len(names)}")
            if not reason.startswith("abi "):    # those are noise; the count is enough
                for entry in names:
                    diag.emit(f"    {entry}")

    seen = {ir.abi for ir in res.injected}
    seen |= {_abi_of(e) for e, _ in res.failed}
    seen |= {_abi_of(e) for e, _ in res.untouched}
    diag.emit("\nPer ABI:")
    for abi in sorted(seen):
        inj = sum(1 for ir in res.injected if ir.abi == abi)
        bad = sum(1 for e, _ in res.failed if _abi_of(e) == abi)
        unt = sum(1 for e, _ in res.untouched if _abi_of(e) == abi)
        if abi in abis:
            mark = ""
        elif abi in SUPPORTED_ABIS:
            mark = "   (not in `abis:`)"
        else:
            mark = "   (unsupported by sopack)"
        diag.emit(f"  {abi:<12} {inj} injected, {bad} skipped, {unt} not selected{mark}")


def _cmd_pack(args: argparse.Namespace, ctx: dict) -> int:
    # Recorded before anything can fail, so the finally block in `main` can name the APK even for
    # a run that died in `load`.
    ctx["input"], ctx["output"] = args.input, args.output

    # The config decides where the log goes, but a broken config is exactly what most needs
    # logging - so `load` runs with only the console handler live and `diag.open_run` replays
    # everything buffered so far once a destination exists. On a ConfigError we open the run with
    # the DEFAULT log settings rather than skipping the record.
    try:
        cfg, source = load(args.config)
    except BaseException:
        # Open the run with DEFAULT log settings so the failure is still recorded - but do NOT
        # put this Config in ctx. It was never in effect, and reporting its `cipher: wbaes` as
        # the run's cipher would describe settings the user's rejected config never supplied.
        diag.open_run(Config.default().logging.file, args.input)
        diag.debug("config load FAILED; see the error below")
        diag.debug(traceback.format_exc())
        raise

    ctx["cfg"] = cfg
    ctx["config_source"] = source
    diag.open_run(cfg.logging.file, args.input)
    diag.log_config(cfg, source)

    # Checked HERE, up front, rather than left to whichever open() fails first. A missing input and
    # an unwritable output both surface as FileNotFoundError from deep inside the pack, and an
    # errno does not say which path it was about - which is how `-o /no/such/dir/o.apk` came to be
    # reported as a missing input. (The message says "input", not "input APK": the input may be an
    # AAB, and at this point it has not even been opened, so we do not yet know which.)
    if not os.path.isfile(args.input):
        what = "is a directory" if os.path.isdir(args.input) else "does not exist"
        raise InputError(f"input {args.input} {what}")

    # APK or AAB, decided by what is INSIDE the file. Done here, before the banner, so the pack
    # announces what it thinks it was handed - and so a file that is neither fails now rather than
    # after rewriting a ~150 MB zip. The descriptor is passed to `repackage`, which would
    # otherwise re-read the central directory to reach the same conclusion.
    cont = detect_container(args.input)
    # Into ctx immediately, not after repackage returns: a pack that raises still gets a run
    # record, and "which format was this?" is part of triaging that failure.
    ctx["container"] = cont.kind

    ks_cfg = cfg.signing.keystore

    # None means auto-select every lib/<abi>/*.so; an empty list is NOT the same thing and
    # config.py refuses to produce one, so this stays a straight pass-through.
    libs = list(cfg.libraries.include) if cfg.libraries.include is not None else None
    excludes = list(cfg.libraries.exclude)

    # Built unconditionally, unlike the old --keystore gate. The config always carries
    # keystore settings, so an alias or password set without a path used to be silently
    # ignored; now it applies to the same default keystore apk.py would have picked.
    ks = KeystoreInfo(path=ks_cfg.path or DEFAULT_KEYSTORE_PATH,
                      alias=ks_cfg.alias,
                      store_pass=ks_cfg.store_pass,
                      key_pass=ks_cfg.key_pass or ks_cfg.store_pass)

    eff_excludes = build_excludes(excludes)
    diag.emit(f"sopack {__version__}: packing {args.input} -> {args.output}")
    diag.emit(f"  config: {source or f'built-in defaults (no {DEFAULT_CONFIG_NAME} found)'}")
    # AAB-only line, deliberately: the APK path's output has to stay byte-for-byte what it was,
    # and for an APK there is nothing to say - it is what this tool has always taken.
    if cont is not APK_CONTAINER:
        diag.emit("  input: Android App Bundle (detected)")
    diag.emit(f"  cipher={cfg.cipher}  abis={','.join(cfg.abis)}")
    diag.emit(f"  libs={'ALL ' + cont.lib_shape if libs is None else ','.join(libs)}")
    diag.emit(f"  excluding: {', '.join(eff_excludes)}")
    # A warning, never an error: the container is decided by content, so a misnamed output is
    # cosmetic - but silently writing a bundle to something called `.apk` is how someone ends up
    # feeding it to `adb install`.
    out_ext = os.path.splitext(args.output)[1].lower()
    if out_ext and out_ext != f".{cont.kind}":
        diag.note_warning(f"WARNING: the input is an {cont.noun} but the output is named "
                          f"{os.path.basename(args.output)} - it will be written as an "
                          f"{cont.noun} regardless")
    # No wb_keygen= : there is no config key for it either, and provision.find_wb_keygen
    # locates one on its own (vendor/wbc/bin/ from a local build, or the bundle it was
    # installed from). repackage still takes the kwarg, so a library caller can pin one.
    res = repackage(args.input, args.output, libs, cipher=cfg.cipher,
                    abis=cfg.abis, keystore=ks, min_sdk=cfg.signing.min_sdk,
                    log=cfg.logging.stub_log,
                    allow_helper_log=cfg.logging.allow_helper_log,
                    exclude_libs=excludes, no_sign=not cfg.signing.sign,
                    logger=diag.emit, container=cont)
    ctx["res"] = res

    diag.emit(f"\nInjected {len(res.injected)} librar{'y' if len(res.injected)==1 else 'ies'}:")
    for ir in res.injected:
        diag.emit(f"  [{ir.abi}] .text rva=0x{ir.text_rva:x} size={ir.text_size} "
                  f"seg=0x{ir.seg_rva:x} entry=0x{ir.entry_rva:x} via {ir.strategy}")
    _print_summary(res, cfg.abis)

    # Cleartext skips are an exit-0 outcome that changes what the artifact IS, so they have to
    # reach the run record too - a batch cannot otherwise tell a clean pack from a degraded one.
    if res.failed:
        diag.note_warning(f"WARNING: {len(res.failed)} selected librar"
                          f"{'y' if len(res.failed) == 1 else 'ies'} could not be injected and "
                          f"ship in CLEARTEXT")

    # signing.verify runs apksigner too, so an unsigned output has nothing to verify and the
    # attempt would fail for the same reason signing did. That covers a bundle for free: sopack
    # never signs one, so res.signed is False and there is nothing to dump.
    if cfg.signing.verify and res.signed:
        diag.emit("\nSignature:")
        diag.emit(verify_signature(args.output, min_sdk=cfg.signing.min_sdk))
    diag.emit(f"\nDone: {args.output}")
    if res.signed:
        diag.emit("Note: re-signed with a new certificate - this is a new app identity "
                  "(cannot update-install over the original).")
    elif cont is not APK_CONTAINER:
        # A bundle is unsigned BY DESIGN, not degraded, so it gets its own advice: apksigner
        # cannot read a bundle at all, and the signature that matters is the app's upload key.
        # Naming the real command matters here - the APK advice below would send someone to a
        # tool that fails with "Missing AndroidManifest.xml" and no hint why.
        diag.emit(f"Note: this {cont.noun} is UNSIGNED, by design - sopack does not hold your "
                  "upload key. Sign it with yours before uploading:")
        diag.emit(f"  jarsigner -keystore <keystore> -signedjar signed.aab {args.output} <alias>")
    else:
        # Last line of output, because it is the one thing that decides what you can do with
        # this file. A packed-but-unsigned APK is a normal pipeline artifact, but `adb install`
        # rejects it with an error that says nothing about signing being skipped here.
        diag.emit("Note: this APK is UNSIGNED and cannot be installed as-is. Sign it before use:")
        diag.emit(f"  apksigner sign --ks <keystore> --out signed.apk {args.output}")
    return exitcodes.OK


def _cmd_init_config(args: argparse.Namespace, ctx: dict) -> int:
    if args.output == "-":
        sys.stdout.write(SAMPLE_YAML)
        return exitcodes.OK
    dest = Path(args.output)
    try:
        # "x" rather than exists()-then-write: the check and the write are one operation, and
        # clobbering a config someone spent time on is not recoverable from here.
        with open(dest, "x", encoding="utf-8") as fh:
            fh.write(SAMPLE_YAML)
    except FileExistsError:
        raise _Usage(f"error: {dest} already exists - delete it first, edit it in place, "
                     f"or write elsewhere with `sopack init-config -o PATH`")
    diag.emit(f"wrote {dest}")
    diag.emit("Every key is set to its default, so packing with it unedited behaves exactly like "
              "packing without it.")
    diag.emit("Edit it, then: sopack pack <in.apk> -o <out.apk>")
    return exitcodes.OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sopack", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"sopack {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("pack",
                        help="encrypt .so libraries inside an APK or AAB (and re-sign an APK)")
    # No --aab / --format flag, and no config key either: the container is decided by what is
    # inside the file (container.detect). A flag would let a caller declare the wrong one, and the
    # single-input-single-output shape of this command is pinned by tests/test_lib_select.py.
    pk.add_argument("input", help="input APK or AAB path (detected from the file)")
    pk.add_argument("-o", "--output", required=True, help="output path, same format as the input")
    pk.add_argument("--config", default=None,
                    help=f"YAML config path. Default: ./{DEFAULT_CONFIG_NAME} if present, "
                         f"else sopack's built-in defaults (cipher wbaes, arm64-v8a, every "
                         f"native library). Run `sopack init-config` to write one.")
    pk.set_defaults(func=_cmd_pack)

    ic = sub.add_parser("init-config",
                        help=f"write a commented {DEFAULT_CONFIG_NAME} you can edit")
    ic.add_argument("-o", "--output", default=DEFAULT_CONFIG_NAME,
                    help=f"where to write it (default ./{DEFAULT_CONFIG_NAME}); "
                         f"'-' writes to stdout. An existing file is never overwritten.")
    ic.set_defaults(func=_cmd_init_config)
    return p


# Exception -> exit code, MOST SPECIFIC FIRST: SelectionError is a NothingPackedError, ConfigError
# is a ValueError, and StubMissingError is a FileNotFoundError, so order is what makes each one
# reachable. A tuple of pairs rather than a dict for exactly that reason - dicts do not express
# precedence, and an isinstance dispatch over one silently depends on insertion order.
_CODE_FOR = (
    (ConfigError, exitcodes.CONFIG),
    (SelectionError, exitcodes.SELECTION),
    (NothingPackedError, exitcodes.NOTHING_ENCRYPTED),
    (StubMissingError, exitcodes.TOOLCHAIN),
    (ProvisionError, exitcodes.TOOLCHAIN),
    (InjectError, exitcodes.INJECT),
    (subprocess.CalledProcessError, exitcodes.SIGNING),
    (zipfile.BadZipFile, exitcodes.INPUT),
    # Both of these are FileNotFoundError subclasses and must precede it. ToolMissingError is a
    # missing apksigner/keytool/zipalign/wb_keygen - a TOOLCHAIN problem, and reporting it as an
    # input error is what made "could not find a host wb_keygen" (the most-hit failure on a fresh
    # checkout) point the reader at their APK instead of their toolchain.
    (ToolMissingError, exitcodes.TOOLCHAIN),
    (InputError, exitcodes.INPUT),
    # Deliberately last among the OSErrors, and note this now catches a BARE FileNotFoundError
    # too: the input is validated up front in _cmd_pack, so an ENOENT reaching here is a path we
    # were told to WRITE. FileNotFoundError is an OSError subclass, so listing it above with
    # INPUT used to shadow this entry entirely.
    (OSError, exitcodes.OUTPUT),
    (ValueError, exitcodes.CONFIG),
    (RuntimeError, exitcodes.INTERNAL),
)


def code_for(exc: BaseException) -> int:
    for kind, code in _CODE_FOR:
        if isinstance(exc, kind):
            return code
    return exitcodes.INTERNAL


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    diag.bootstrap()
    # ctx collects whatever the command managed to establish before failing, so the finally block
    # can write a report for a run that died halfway - which is the run you most want a record of.
    ctx: dict = {"cfg": None, "res": None, "config_source": None}
    started = time.time()
    code = exitcodes.INTERNAL
    error: str | None = None
    try:
        _reject_removed_flags(argv)
        args = build_parser().parse_args(argv)
        try:
            code = args.func(args, ctx)
            return code
        # ConfigError is a ValueError, so a bad config key prints as `error: ...` rather than a
        # traceback. CalledProcessError is in the tuple because signing.verify defaults to true:
        # verify_signature runs apksigner with check=True, so without this an apksigner hiccup
        # turns an otherwise successful pack into a raw traceback - after the output APK has
        # already been written.
        except (FileNotFoundError, RuntimeError, ValueError, OSError,
                zipfile.BadZipFile, subprocess.CalledProcessError) as e:
            code = code_for(e)
            error = str(e)
            # NothingPackedError carries the partial result. Recovering it here is what lets a
            # code-6 report list every candidate and the reason it was skipped, instead of a bare
            # "nothing was packed" plus a message that points at terminal output.
            if ctx.get("res") is None and getattr(e, "result", None) is not None:
                ctx["res"] = e.result
            # The terminal keeps its one-line message; the log gets the traceback, which is the
            # difference between "error: X" and knowing which of six call paths produced X.
            diag.debug(f"failed with {type(e).__name__} -> exit {code} "
                       f"({exitcodes.slug(code)})")
            diag.debug(traceback.format_exc())
            diag.warn(f"error: {e}")
            return code
        except Exception as e:                  # genuinely unmodelled: keep the traceback visible
            code, error = exitcodes.INTERNAL, str(e)
            diag.debug(traceback.format_exc())
            raise
    except _Usage as e:
        # Re-raised, not returned: three existing tests assert `pytest.raises(SystemExit)` here,
        # and .code is already 2 so the process exits correctly. Python prints nothing for an int
        # code, hence the explicit warn.
        code, error = exitcodes.USAGE, str(e)
        diag.warn(str(e))
        raise
    except SystemExit as e:
        # argparse's own exit (usage errors, --help, --version). Preserve its code verbatim: 0 for
        # --help/--version, 2 for a usage error, which is why nothing else may claim 2.
        code = e.code if isinstance(e.code, int) else exitcodes.USAGE
        raise
    finally:
        # Recorded even on failure, and even for a partial run: a batch triages from these, so a
        # pack that died is exactly the one that must leave a line behind. Wrapped because a bug
        # in the reporting layer must never replace the real diagnosis.
        try:
            if diag.run_dir():
                report.finalize(ctx.get("cfg"), ctx.get("res"),
                                input_apk=ctx.get("input"), output_apk=ctx.get("output"),
                                exit_code=code, error=error,
                                config_source=ctx.get("config_source"),
                                container=ctx.get("container"),
                                duration_ms=int((time.time() - started) * 1000))
        except Exception:                                   # pragma: no cover - defensive
            diag.debug("could not finalize the run report:\n" + traceback.format_exc())
        diag.reset()


if __name__ == "__main__":
    sys.exit(main())
