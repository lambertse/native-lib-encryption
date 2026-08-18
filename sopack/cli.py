"""sopack command-line interface.

    sopack pack in.apk -o out.apk [--lib NAME | --libs libs.txt] [options]

Library selection is OPTIONAL. Omit --lib/--libs and every lib/<abi>/*.so in the input
APK is encrypted, for the ABIs --abi selects (default arm64-v8a alone).

`--libs` is a text file (one entry per line; blank lines and '#' comments ignored).
Each entry is either a full APK path (lib/arm64-v8a/libfoo.so) or a bare basename
(libfoo.so, which matches that library across every selected ABI).

`--exclude-lib` takes fnmatch globs on the basename (a trailing .so is optional) and
always wins over selection, including over an explicit --lib.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from . import __version__
from .apk import (DEFAULT_EXCLUDE_PATTERNS, KeystoreInfo, build_excludes, repackage,
                  verify_signature)
from .stubs import DEFAULT_ABIS, SUPPORTED_ABIS


def _read_libs(path: str) -> list[str]:
    libs = []
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        libs.append(line)
    if not libs:
        raise SystemExit(f"error: no libraries listed in {path}")
    return libs


def _split_list(values) -> list[str]:
    """Flatten a repeatable, optionally comma-separated argparse `append` list."""
    return [item.strip() for entry in (values or [])
            for item in entry.split(",") if item.strip()]


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
            mark = "   (not in --abi)"
        else:
            mark = "   (unsupported by sopack)"
        print(f"  {abi:<12} {inj} injected, {bad} skipped, {unt} not selected{mark}")


def _cmd_pack(args: argparse.Namespace) -> int:
    if args.libs:
        # An explicitly passed but empty file is a user error, not a request for
        # auto-select: _read_libs raises rather than returning [].
        libs = _read_libs(args.libs)
    elif args.lib:
        # --lib is repeatable AND accepts a comma-separated list (like --abi), so
        # `--lib a.so,b.so`, `--lib a.so --lib b.so`, and a mix all work.
        libs = _split_list(args.lib)
        if not libs:
            raise SystemExit("error: --lib was given but named no libraries")
    else:
        libs = None                     # auto-select every lib/<abi>/*.so
    excludes = _split_list(args.exclude_lib)

    if args.abi == "all":
        abis = SUPPORTED_ABIS
    elif args.abi:
        abis = tuple(args.abi.split(","))
    else:
        abis = DEFAULT_ABIS
    for a in abis:
        if a not in SUPPORTED_ABIS:
            raise SystemExit(f"error: unsupported ABI {a!r}; choose from {SUPPORTED_ABIS}")

    ks = None
    if args.keystore:
        ks = KeystoreInfo(path=args.keystore, alias=args.ks_alias,
                          store_pass=args.ks_pass, key_pass=args.key_pass or args.ks_pass)

    eff_excludes = build_excludes(excludes, args.no_default_exclude)
    print(f"sopack {__version__}: packing {args.input} -> {args.output}")
    print(f"  cipher={args.cipher}  abis={','.join(abis)}"
          + ("" if args.abi else "  (default; --abi all for every supported ABI)"))
    print(f"  libs={'ALL lib/<abi>/*.so' if libs is None else ','.join(libs)}")
    print(f"  excluding: {', '.join(eff_excludes)}")
    # No wb_keygen= : the flag is gone and provision.find_wb_keygen locates one on its own
    # (vendor/wbc/bin/ from a local build, or the bundle it was installed from). repackage still
    # takes the kwarg, so a library caller can pin one.
    res = repackage(args.input, args.output, libs, cipher=args.cipher,
                    abis=abis, keystore=ks, min_sdk=args.min_sdk, log=args.log,
                    allow_helper_log=args.allow_helper_log,
                    exclude_libs=excludes, no_default_exclude=args.no_default_exclude,
                    no_sign=args.no_sign)

    print(f"\nInjected {len(res.injected)} librar{'y' if len(res.injected)==1 else 'ies'}:")
    for ir in res.injected:
        print(f"  [{ir.abi}] .text rva=0x{ir.text_rva:x} size={ir.text_size} "
              f"seg=0x{ir.seg_rva:x} entry=0x{ir.entry_rva:x} via {ir.strategy}")
    _print_summary(res, abis)

    # --verify runs apksigner too, so an unsigned output has nothing to verify and the attempt
    # would fail for the same reason signing did.
    if args.verify and res.signed:
        print("\nSignature:")
        print(verify_signature(args.output, min_sdk=args.min_sdk))
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sopack", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"sopack {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("pack", help="encrypt .so libraries inside an APK and re-sign")
    pk.add_argument("input", help="input APK path")
    pk.add_argument("-o", "--output", required=True, help="output APK path")
    g = pk.add_mutually_exclusive_group()
    g.add_argument("--libs", help="text file listing .so to encrypt (one per line). "
                                  "Omit both --libs and --lib to encrypt every "
                                  "lib/<abi>/*.so in the APK.")
    g.add_argument("--lib", action="append",
                   help="a .so to encrypt; repeatable and/or comma-separated "
                        "(e.g. --lib libfoo.so,libbar.so). Omit to encrypt every "
                        "lib/<abi>/*.so in the APK.")
    pk.add_argument("--exclude-lib", action="append",
                    help="never encrypt these; repeatable and/or comma-separated, "
                         "fnmatch globs on the basename with an optional .so "
                         "(e.g. --exclude-lib 'libc++_shared,libmy*'). Wins over "
                         "--lib/--libs as well as over auto-select. Always applied on top "
                         f"of the built-ins: {', '.join(DEFAULT_EXCLUDE_PATTERNS)}, libsopk_*")
    pk.add_argument("--no-default-exclude", action="store_true",
                    help="drop the built-in exclusion list "
                         f"({', '.join(DEFAULT_EXCLUDE_PATTERNS)}). sopack's own injected "
                         "artifacts (libsopk_*) stay excluded regardless.")
    pk.add_argument("--cipher", choices=["chacha20", "xor", "wbaes"], default="wbaes",
                    help="wbaes (DEFAULT): white-box AES-128 key wrapping via an injected "
                         "helper - the long-term key is sealed and never reconstructed, and "
                         "the white-box unwraps a session key that ChaCha20-decrypts .text. "
                         "Needs the artifacts ./scripts/build_wbaes.sh produces (a host "
                         "wb_keygen and this ABI's skeletons); a portable bundle carries them "
                         "already. chacha20/xor: the freestanding stub, no white-box and no "
                         "build step, but the raw key ships in the binary (whitened).")
    pk.add_argument("--abi",
                    help=f"comma list, or 'all'; default {','.join(DEFAULT_ABIS)} "
                         f"(the only ABI protected in practice); "
                         f"supported {','.join(SUPPORTED_ABIS)}")
    pk.add_argument("--min-sdk", type=int, default=None,
                    help="override apksigner minSdkVersion (if manifest detection fails)")
    pk.add_argument("--log", action="store_true",
                    help="stub emits a logcat line (tag 'sopack') on successful decrypt")
    pk.add_argument("--allow-helper-log", action="store_true",
                    help="(--cipher wbaes) permit a helper skeleton built with -DSOPK_RT_LOG. "
                         "Such a helper logs the target name, .text address and size to logcat, "
                         "so packing one is refused by default. Use it for on-device Phase 6 "
                         "verification only - the resulting APK is NOT shippable.")
    pk.add_argument("--keystore", help="keystore path (auto-generated if missing)")
    pk.add_argument("--ks-alias", default="sopack")
    pk.add_argument("--ks-pass", default="sopack")
    pk.add_argument("--key-pass", default=None)
    # store_true/store_false rather than BooleanOptionalAction: the latter needs 3.9, which is
    # exactly this project's floor (pyproject.toml requires-python), leaving no margin.
    pk.add_argument("--verify", action="store_true", default=True,
                    help="print signer certs after signing (DEFAULT; --no-verify to skip)")
    pk.add_argument("--no-verify", action="store_false", dest="verify",
                    help="skip the post-signing apksigner verify")
    pk.add_argument("--no-sign", action="store_true",
                    help="do not sign the output; leave an UNSIGNED APK for a later signing "
                         "step. Signing is best-effort anyway - without apksigner sopack warns "
                         "and leaves it unsigned - but this makes the intent explicit and "
                         "skips generating a debug keystore")
    pk.set_defaults(func=_cmd_pack)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    # CalledProcessError is in the tuple because --verify is now the DEFAULT: verify_signature
    # runs apksigner with check=True, so without this an apksigner hiccup turns an otherwise
    # successful pack into a raw traceback - after the output APK has already been written.
    except (FileNotFoundError, RuntimeError, ValueError,
            subprocess.CalledProcessError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
