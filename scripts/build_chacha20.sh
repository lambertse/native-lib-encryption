#!/usr/bin/env bash
#
# build_chacha20.sh — get the freestanding-stub ciphers (`--cipher chacha20`, `--cipher xor`)
# to a packable state: build the per-ABI stub blobs, run the tests, print the pack command.
#
# Deliberately thin, and that is the point of comparing it with build_wbaes.sh: the stub ciphers
# need no provisioning, no second repo and no per-ABI helper. Their key ships inside the library
# (whitened at rest), which is exactly the weakness `--cipher wbaes` exists to remove — at the
# cost of everything build_wbaes.sh has to check.
#
# Usage:
#   ./scripts/build_chacha20.sh                 # NDK from the environment, or plain LLVM on PATH
#   ./scripts/build_chacha20.sh --api 24
#   ./scripts/build_chacha20.sh --ndk ~/Library/Android/sdk/ndk/29.0.14206865
#
# Options:
#   --ndk PATH      Android NDK root. Else $ANDROID_NDK_HOME / $ANDROID_NDK_ROOT / $NDK.
#                   Omit entirely to build with clang + llvm-objcopy + llvm-readelf from PATH,
#                   which stub/build_stubs.sh also accepts (the stub is freestanding, so it
#                   needs no Android sysroot).
#   --api N         default 24
#   --skip-tests    skip the unit tests
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOPACK="$(cd "$HERE/.." && pwd)"
# shellcheck source=scripts/_common.sh
. "$HERE/_common.sh"

API=24
SKIP_TESTS=0
NDK_ARG=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --ndk)        NDK_ARG="$2"; shift 2 ;;
        --api)        API="$2"; shift 2 ;;
        --skip-tests) SKIP_TESTS=1; shift ;;
        -h|--help)    sed -n '2,28p' "$0"; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

say "preflight"
need python3
( cd "$SOPACK" && python3 -c 'import sopack' >/dev/null 2>&1 ) \
    || die "cannot import sopack from $SOPACK — run: pip install -e ."

NDK="${NDK_ARG:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${NDK:-}}}}"
if [ -n "$NDK" ]; then
    [ -d "$NDK" ] || die "NDK=$NDK does not exist"
    info "toolchain: NDK ($NDK)"
    export ANDROID_NDK_HOME="$NDK"
else
    for t in clang llvm-objcopy llvm-readelf; do
        need "$t" "no NDK given, so build_stubs.sh needs plain LLVM on PATH"
    done
    info "toolchain: plain LLVM on PATH"
fi

# Note this REWRITES tracked files: sopack/stubs/stub_<abi>.bin/.json are package data and are
# committed. Rebuilding with a different LLVM produces different (still valid) blobs, so expect
# a dirty tree afterwards and only commit them if you meant to.
say "building the per-ABI stub blobs (api $API) — this rewrites tracked sopack/stubs/stub_*"
( cd "$SOPACK" && bash stub/build_stubs.sh "$API" ) \
    || die "stub/build_stubs.sh failed — it hard-fails on any relocation, undefined symbol or
       (arm64) adrp, which is deliberate: the stub has no load bias and cannot tolerate them"

for f in "$SOPACK"/sopack/stubs/stub_*.bin; do
    [ -f "$f" ] || die "no stub blobs produced in sopack/stubs/"
    ok "$(basename "$f") ($(wc -c <"$f" | tr -d ' ') bytes)"
done

if [ "$SKIP_TESTS" -eq 1 ]; then
    warn "tests skipped by --skip-tests"
else
    say "unit tests"
    ( cd "$SOPACK" && python3 -m pytest tests/ -q ) || die "unit tests failed"
    ok "unit tests pass"
fi

cat <<EOF

==> Stub blobs ready. Pack with:

  cd "$SOPACK"
  mkdir -p output
  python3 -m sopack.cli pack <your.apk> \\
    --lib "libfoo.so,libbar.so" \\
    --cipher chacha20 \\
    --abi arm64-v8a \\
    -o output/packed.apk \\
    --log \\
    --verify

  Quote the --lib list: it is ONE argv word, so an unquoted space after a comma makes
  argparse reject the second name.
  --log makes the stub emit a logcat confirmation line; drop it for a silent stub.

Unlike --cipher wbaes, the key ships inside each packed library (whitened, not plaintext).
See docs/architecture.md §9 for what that does and does not buy you.
EOF
