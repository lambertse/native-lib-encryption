"""sopack command-line interface.

    sopack pack in.apk -o out.apk [--config PATH]
    sopack init-config [-o PATH]

The command line carries only the input and output APK. Every other setting - cipher, ABIs,
library selection, keystore, signing and logging - lives in a YAML config file. sopack reads
`--config PATH` if given (an error if it does not exist), else `./config.yaml`, else its
built-in defaults.

`sopack init-config` writes a fully commented config.yaml, every key set to its default, so
an unedited one packs exactly like a bare `sopack pack`. `config.sample.yaml` in the repo is
the same file.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from . import __version__
from .apk import (DEFAULT_KEYSTORE_PATH, KeystoreInfo, build_excludes, repackage,
                  verify_signature)
from .config import DEFAULT_CONFIG_NAME, SAMPLE_YAML, load
from .stubs import SUPPORTED_ABIS

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
            raise SystemExit(
                f"error: {flag} was removed - sopack is configured by a YAML file now.\n"
                f"       Set `{replacement}` in {DEFAULT_CONFIG_NAME} instead.\n"
                f"       Run `sopack init-config` to write a commented one.")
        prev = arg


def _abi_of(entry: str) -> str:
    parts = entry.split("/")
    return parts[1] if len(parts) > 2 else "?"


def _print_summary(res, abis) -> None:
    """Per-ABI account of what got protected and what shipped in cleartext.

    A bare "Injected N libraries" reads as "the app is protected". Only arm64-v8a is
    protected in practice, so every library left in cleartext has to be visible here -
    with the reason - rather than silently dropped from the report.
    """
    if res.failed:
        print("\nSkipped (selected but could not be injected - these ship in CLEARTEXT):")
        for entry, err in res.failed:
            print(f"  {entry}: {err}")
    if res.untouched:
        by_reason: dict[str, list[str]] = {}
        for entry, reason in res.untouched:
            by_reason.setdefault(reason, []).append(entry)
        print("\nNot selected:")
        for reason in sorted(by_reason):
            names = by_reason[reason]
            print(f"  {reason}: {len(names)}")
            if not reason.startswith("abi "):    # those are noise; the count is enough
                for entry in names:
                    print(f"    {entry}")

    seen = {ir.abi for ir in res.injected}
    seen |= {_abi_of(e) for e, _ in res.failed}
    seen |= {_abi_of(e) for e, _ in res.untouched}
    print("\nPer ABI:")
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
        print(f"  {abi:<12} {inj} injected, {bad} skipped, {unt} not selected{mark}")


def _cmd_pack(args: argparse.Namespace) -> int:
    cfg, source = load(args.config)
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
    print(f"sopack {__version__}: packing {args.input} -> {args.output}")
    print(f"  config: {source or f'built-in defaults (no {DEFAULT_CONFIG_NAME} found)'}")
    print(f"  cipher={cfg.cipher}  abis={','.join(cfg.abis)}")
    print(f"  libs={'ALL lib/<abi>/*.so' if libs is None else ','.join(libs)}")
    print(f"  excluding: {', '.join(eff_excludes)}")
    # No wb_keygen= : there is no config key for it either, and provision.find_wb_keygen
    # locates one on its own (vendor/wbc/bin/ from a local build, or the bundle it was
    # installed from). repackage still takes the kwarg, so a library caller can pin one.
    res = repackage(args.input, args.output, libs, cipher=cfg.cipher,
                    abis=cfg.abis, keystore=ks, min_sdk=cfg.signing.min_sdk,
                    log=cfg.logging.stub_log,
                    allow_helper_log=cfg.logging.allow_helper_log,
                    exclude_libs=excludes, no_sign=not cfg.signing.sign)

    print(f"\nInjected {len(res.injected)} librar{'y' if len(res.injected)==1 else 'ies'}:")
    for ir in res.injected:
        print(f"  [{ir.abi}] .text rva=0x{ir.text_rva:x} size={ir.text_size} "
              f"seg=0x{ir.seg_rva:x} entry=0x{ir.entry_rva:x} via {ir.strategy}")
    _print_summary(res, cfg.abis)

    # signing.verify runs apksigner too, so an unsigned output has nothing to verify and the
    # attempt would fail for the same reason signing did.
    if cfg.signing.verify and res.signed:
        print("\nSignature:")
        print(verify_signature(args.output, min_sdk=cfg.signing.min_sdk))
    print(f"\nDone: {args.output}")
    if res.signed:
        print("Note: re-signed with a new certificate - this is a new app identity "
              "(cannot update-install over the original).")
    else:
        # Last line of output, because it is the one thing that decides what you can do with
        # this file. A packed-but-unsigned APK is a normal pipeline artifact, but `adb install`
        # rejects it with an error that says nothing about signing being skipped here.
        print("Note: this APK is UNSIGNED and cannot be installed as-is. Sign it before use:")
        print(f"  apksigner sign --ks <keystore> --out signed.apk {args.output}")
    return 0


def _cmd_init_config(args: argparse.Namespace) -> int:
    if args.output == "-":
        sys.stdout.write(SAMPLE_YAML)
        return 0
    dest = Path(args.output)
    try:
        # "x" rather than exists()-then-write: the check and the write are one operation, and
        # clobbering a config someone spent time on is not recoverable from here.
        with open(dest, "x", encoding="utf-8") as fh:
            fh.write(SAMPLE_YAML)
    except FileExistsError:
        raise SystemExit(f"error: {dest} already exists - delete it first, edit it in place, "
                         f"or write elsewhere with `sopack init-config -o PATH`")
    print(f"wrote {dest}")
    print("Every key is set to its default, so packing with it unedited behaves exactly like "
          "packing without it.")
    print("Edit it, then: sopack pack <in.apk> -o <out.apk>")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sopack", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"sopack {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("pack", help="encrypt .so libraries inside an APK and re-sign")
    pk.add_argument("input", help="input APK path")
    pk.add_argument("-o", "--output", required=True, help="output APK path")
    pk.add_argument("--config", default=None,
                    help=f"YAML config path. Default: ./{DEFAULT_CONFIG_NAME} if present, "
                         f"else sopack's built-in defaults (cipher wbaes, arm64-v8a, every "
                         f"lib/<abi>/*.so). Run `sopack init-config` to write one.")
    pk.set_defaults(func=_cmd_pack)

    ic = sub.add_parser("init-config",
                        help=f"write a commented {DEFAULT_CONFIG_NAME} you can edit")
    ic.add_argument("-o", "--output", default=DEFAULT_CONFIG_NAME,
                    help=f"where to write it (default ./{DEFAULT_CONFIG_NAME}); "
                         f"'-' writes to stdout. An existing file is never overwritten.")
    ic.set_defaults(func=_cmd_init_config)
    return p


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    _reject_removed_flags(argv)
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    # ConfigError is a ValueError, so a bad config key prints as `error: ...` rather than a
    # traceback. CalledProcessError is in the tuple because signing.verify defaults to true:
    # verify_signature runs apksigner with check=True, so without this an apksigner hiccup
    # turns an otherwise successful pack into a raw traceback - after the output APK has
    # already been written.
    except (FileNotFoundError, RuntimeError, ValueError,
            subprocess.CalledProcessError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
