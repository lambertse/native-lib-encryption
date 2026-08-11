"""sopack command-line interface.

    sopack pack in.apk --libs libs.txt -o out.apk [options]

`--libs` is a text file (one entry per line; blank lines and '#' comments ignored).
Each entry is either a full APK path (lib/arm64-v8a/libfoo.so) or a bare basename
(libfoo.so, which matches that library across every selected ABI).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .apk import KeystoreInfo, repackage, verify_signature
from .stubs import SUPPORTED_ABIS


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


def _cmd_pack(args: argparse.Namespace) -> int:
    if args.libs:
        libs = _read_libs(args.libs)
    else:
        # --lib is repeatable AND accepts a comma-separated list (like --abi), so
        # `--lib a.so,b.so`, `--lib a.so --lib b.so`, and a mix all work.
        libs = [name.strip() for entry in (args.lib or [])
                for name in entry.split(",") if name.strip()]
    if not libs:
        raise SystemExit("error: provide --libs FILE or one or more --lib NAME")
    abis = tuple(args.abi.split(",")) if args.abi else SUPPORTED_ABIS
    for a in abis:
        if a not in SUPPORTED_ABIS:
            raise SystemExit(f"error: unsupported ABI {a!r}; choose from {SUPPORTED_ABIS}")

    ks = None
    if args.keystore:
        ks = KeystoreInfo(path=args.keystore, alias=args.ks_alias,
                          store_pass=args.ks_pass, key_pass=args.key_pass or args.ks_pass)

    print(f"sopack {__version__}: packing {args.input} -> {args.output}")
    print(f"  cipher={args.cipher}  abis={','.join(abis)}")
    res = repackage(args.input, args.output, libs, cipher=args.cipher,
                    abis=abis, keystore=ks, min_sdk=args.min_sdk, log=args.log,
                    wb_keygen=args.wb_keygen, allow_helper_log=args.allow_helper_log)

    print(f"\nInjected {len(res.injected)} librar{'y' if len(res.injected)==1 else 'ies'}:")
    for ir in res.injected:
        print(f"  [{ir.abi}] .text rva=0x{ir.text_rva:x} size={ir.text_size} "
              f"seg=0x{ir.seg_rva:x} entry=0x{ir.entry_rva:x} via {ir.strategy}")
    if res.skipped:
        print(f"  ({len(res.skipped)} other .so entries left untouched)")

    if args.verify:
        print("\nSignature:")
        print(verify_signature(args.output, min_sdk=args.min_sdk))
    print(f"\nDone: {args.output}")
    print("Note: re-signed with a new certificate - this is a new app identity "
          "(cannot update-install over the original).")
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
    g.add_argument("--libs", help="text file listing .so to encrypt (one per line)")
    g.add_argument("--lib", action="append",
                   help="a .so to encrypt; repeatable and/or comma-separated "
                        "(e.g. --lib libfoo.so,libbar.so)")
    pk.add_argument("--cipher", choices=["chacha20", "xor", "wbaes"], default="chacha20",
                    help="chacha20/xor: freestanding stub (raw key ships whitened). "
                         "wbaes: white-box AES-128 key wrapping via an injected helper - the "
                         "long-term key is sealed and never reconstructed, and the white-box "
                         "unwraps a session key that ChaCha20-decrypts .text. Requires "
                         "whitebox-cryptography >= 3.0.0 for both assets/wbc/ and the helper "
                         "skeleton (2.0.0 removed the bulk API and bumped the blob to v3, so "
                         "1.x artifacts will not link or load).")
    pk.add_argument("--wb-keygen", default=None,
                    help="path to a HOST wb_keygen (for --cipher wbaes); else "
                         "$SOPACK_WBKEYGEN or one on PATH")
    pk.add_argument("--abi", help=f"comma list; default {','.join(SUPPORTED_ABIS)}")
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
    pk.add_argument("--verify", action="store_true", help="print signer certs after signing")
    pk.set_defaults(func=_cmd_pack)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
