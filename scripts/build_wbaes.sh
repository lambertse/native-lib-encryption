#!/usr/bin/env bash
#
# build_wbaes.sh - get `cipher: wbaes` from a clean checkout to a packable state, running
# Phases 1-4 of docs/technical/WBAES.md and every one of their PASS checks. It stops before
# packing (that needs YOUR APK and lib names) and prints the Phase-5 command to run next.
#
# Why a script: the failure modes of this mode are unforgiving and mostly SILENT. A pre-3.0.0
# libwbcrypto.a links cleanly and only breaks on device; a CACHED pre-3.0.0 host wb_keygen or
# archive survives an SDK upgrade and silently seals a heavy/v3 blob; a stale helper skeleton
# aborts on device naming the wrong cause; the wrong compiler driver leaves the whole C++
# runtime unresolved.
# Each of those has cost a debugging session here, so each is a hard gate below.
#
# WBC is a PINNED SUBMODULE at third_party/whitebox-cryptography - this script initialises it
# on demand, so a clean clone needs no arguments and no out-of-band drop. It needs network the
# first time: WBC's own third_party/fetch_deps.sh downloads libsodium and the O-MVLL plugin.
#
# Usage:
#   ./scripts/build_wbaes.sh                          # submodule + NDK from the environment
#   NDK=~/ndk/29 ./scripts/build_wbaes.sh
#   ./scripts/build_wbaes.sh --wbc ~/src/wbc --ndk ~/ndk/29     # an external WBC working copy
#
# Options:
#   --wbc PATH      whitebox-cryptography checkout (>= 3.0.0). Else $WBC, else the pinned
#                   submodule, else a sibling ../whitebox-cryptography, else prompt.
#   --ndk PATH      Android NDK root.               Else $NDK/$ANDROID_NDK_HOME/
#                   $ANDROID_NDK_ROOT, else prompt.
#   --abi ABI       default arm64-v8a
#   --api N         default 24
#   --release       build the skeleton WITHOUT -DSOPK_RT_LOG (no logcat tracing, no liblog).
#                   This is the DEFAULT - a tracing helper logs the target name, .text address
#                   and size to logcat, and `sopack pack` refuses to pack one.
#   --trace         opt into the tracing build for on-device Phase 6 verification. The result
#                   needs `logging.allow-helper-log: true` in the pack config, and is
#                   NOT shippable.
#   --omvll         configure the Android build WITH the O-MVLL obfuscation plugin. This is the
#                   DEFAULT - the provider is the artifact whose static analysis matters most.
#                   WBC fetches and configures the plugin itself; it only loads on macOS.
#   --no-omvll      build the Android library unobfuscated. Required on Linux (the plugin is a
#                   Mach-O dylib), and the resulting provider is NOT what you should ship.
#   --skip-tests    skip Phase 2 (the unit tests)
#   --host-only     run Phases 1-3 only and stop. Needs no NDK, no cmake and no ninja, so the
#                   Python<->C contracts can be verified on a machine that cannot cross-compile
#                   (CI, for instance). No skeleton is produced, so you cannot pack afterwards.
#   --force         redo cached phases (host wb_keygen, Android libwbcrypto.a)
#
# SOPACK is this script's own repo - never asked for.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOPACK="$(cd "$HERE/.." && pwd)"
# shellcheck source=scripts/_common.sh
. "$HERE/_common.sh"

ABI="arm64-v8a"
API=24
RELEASE=1
OMVLL=1
SKIP_TESTS=0
HOST_ONLY=0
FORCE=0
FIPS_VECTOR="69c4e0d86a7b0430d8cdb78070b4c55a"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --wbc)        WBC="$2"; shift 2 ;;
        --ndk)        NDK="$2"; shift 2 ;;
        --abi)        ABI="$2"; shift 2 ;;
        --api)        API="$2"; shift 2 ;;
        --release)    RELEASE=1; shift ;;          # now the default; kept for explicitness
        --trace)      RELEASE=0; shift ;;
        --omvll)      OMVLL=1; shift ;;          # now the default; kept for explicitness
        --no-omvll)   OMVLL=0; shift ;;
        --skip-tests) SKIP_TESTS=1; shift ;;
        --host-only)  HOST_ONLY=1; shift ;;
        --force)      FORCE=1; shift ;;
        # 2..46 is the header comment block; it ends at the "SOPACK is this script's own
        # repo" line, immediately before `set -euo pipefail`. Widen this if the header grows,
        # or --help starts printing shell code.
        # 2..47 is the header comment block, ending the line before `set -euo pipefail`.
        # Adjust if the header grows, or --help truncates / starts printing shell code.
        -h|--help)    sed -n '2,47p' "$0"; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

TMP="$(mktemp -d "${TMPDIR:-/tmp}/sopack-wbaes.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# ---- validators ------------------------------------------------------------------------
# valid_wbc lives in _common.sh - device_test.sh and artifact_generation.sh gate on it too, and
# three copies of a version check is exactly the drift the submodule exists to remove.

valid_ndk() {
    [ -d "$1" ] || { warn "$1 is not a directory"; return 1; }
    [ -f "$1/build/cmake/android.toolchain.cmake" ] || {
        warn "$1 has no build/cmake/android.toolchain.cmake - not an NDK root"; return 1; }
    return 0
}

# ---- preflight -------------------------------------------------------------------------
say "preflight"

# Resolved here rather than at first use, so a typo fails before any toolchain check.
case "$ABI" in
    arm64-v8a)   ABI_TRIPLE="aarch64-linux-android" ;;
    armeabi-v7a) ABI_TRIPLE="armv7a-linux-androideabi" ;;
    x86_64)      ABI_TRIPLE="x86_64-linux-android" ;;
    *) die "unsupported --abi $ABI (choose arm64-v8a, armeabi-v7a or x86_64)" ;;
esac

need python3
need git "the whitebox-cryptography dependency is a pinned submodule"
need cc  "the Phase 3 round-trip probe is C"
need c++ "libwbcrypto is C++"
# WBC's third_party/fetch_deps.sh downloads libsodium (and the O-MVLL plugin) on first build.
# Fail here rather than 200 lines into a CMake configure.
need curl "WBC's third_party/fetch_deps.sh downloads libsodium on the first build"
need tar  "WBC's third_party/fetch_deps.sh unpacks the dependency tarballs"
if [ "$HOST_ONLY" -eq 0 ]; then
    need cmake "scripts/build_android.sh uses CMake (or pass --host-only)"
    need ninja "scripts/build_android.sh configures with -GNinja (or pass --host-only)"
fi
have openssl || warn "no openssl on PATH - the pack-side cipher falls back to pure Python
      (~0.6 MB/s), so packing a multi-MB .text will be slow but still correct"

( cd "$SOPACK" && python3 -c 'import sopack' >/dev/null 2>&1 ) \
    || die "cannot import sopack from $SOPACK - run: pip install -e ."

: "${NDK:=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
# Initialises the pinned submodule when WBC was not supplied. Not a numbered phase on purpose:
# TOTAL stays 4 so the epilogue's "Host phases 1-4 PASS" sentinel - which device_test.sh and
# artifact_generation.sh both grep for - keeps its wording.
resolve_wbc "$SOPACK"

# Google ships an NDK per host, and the tag is literally "-x86_64" on both: macOS NDKs carry
# darwin-x86_64 (which runs under Rosetta on Apple Silicon) and Linux NDKs linux-x86_64. There
# is no linux-aarch64 prebuilt at all, so an aarch64 Linux host has no usable NDK - say that
# here rather than letting it surface as "wrong NDK layout?" two lines down.
HOSTTAG="$(uname | tr '[:upper:]' '[:lower:]')-x86_64"
if [ "$HOST_ONLY" -eq 0 ] && [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" != "x86_64" ]; then
    die "this is Linux/$(uname -m), and the NDK has no linux-$(uname -m) toolchain - Google
       publishes linux-x86_64 only. Cross-building the Android artifacts needs an x86_64 Linux
       host (see docker/README.md), a Mac, or --host-only to stop after Phase 3."
fi
if [ "$HOST_ONLY" -eq 0 ]; then
    ask_path NDK "Android NDK root: " valid_ndk \
        "Pass --ndk PATH, export NDK / ANDROID_NDK_HOME, or run with --host-only."
    NDKBIN="$NDK/toolchains/llvm/prebuilt/$HOSTTAG/bin"
    # A macOS NDK bind-mounted into a Linux container is the trap this catches: it contains only
    # prebuilt/darwin-x86_64, whose binaries are Mach-O. Naming the tag is what makes that legible.
    [ -d "$NDKBIN" ] || die "no toolchain at $NDKBIN (host tag $HOSTTAG) - wrong NDK layout?
       NDKs are per-host and not interchangeable: if $NDK was installed on a Mac it has only
       toolchains/llvm/prebuilt/darwin-x86_64 and cannot be used from Linux. Install a Linux NDK."
    CXX="$NDKBIN/clang++"
    READELF="$NDKBIN/llvm-readelf"
    [ -x "$CXX" ] || die "no clang++ at $CXX"
    [ -x "$READELF" ] || die "no llvm-readelf at $READELF"

    # O-MVLL is fetched and configured by WBC's build_android.sh (it defaults OMVLL_CONFIG and
    # OMVLL_PYTHONPATH to in-repo paths), so do NOT duplicate those checks here. What it cannot
    # fix is a host upstream publishes no plugin for. There are two: macOS (Mach-O dylib) and
    # Linux/x86_64 (ELF .so), and WBC picks between them itself - so this gate is now only about
    # refusing the hosts that have neither.
    if [ "$OMVLL" -eq 1 ]; then
        case "$(uname -s)/$(uname -m)" in
            Darwin/*)      ;;
            Linux/x86_64)  ;;
            *) die "--omvll (the default) needs macOS or Linux/x86_64: those are the only hosts
       O-MVLL 1.9.1 publishes a plugin for, and it is dlopen'd into the NDK's clang so a
       foreign-arch build cannot substitute. This host is $(uname -s)/$(uname -m). Pass
       --no-omvll to build here - but the resulting provider is UNOBFUSCATED and should not be
       shipped; generate release artifacts on a supported host." ;;
        esac
    fi
    # No PYTHONHOME warning here on purpose: build_android.sh already emits one, and it does so
    # only on the path that actually loads the plugin. Duplicating it in preflight fired twice
    # on a real build and, worse, fired at all when Phase 4 goes on to REUSE a cached
    # libwbcrypto.a and never runs the plugin - a warning about a step that does not happen.
fi

TOTAL=4
[ "$HOST_ONLY" -eq 1 ] && TOTAL=3

info "SOPACK  $SOPACK"
info "WBC     $WBC"
if [ "$HOST_ONLY" -eq 1 ]; then
    info "NDK     (not needed: --host-only stops after Phase 3)"
else
    info "NDK     $NDK  ($HOSTTAG)"
fi
info "target  $ABI / android-$API"
if [ "$RELEASE" -eq 1 ]; then info "skeleton RELEASE (no tracing, stripped)"
else warn "skeleton TRACING (-DSOPK_RT_LOG -llog) - needs 'pack --allow-helper-log'; NOT shippable"; fi

# ---- Phase 1 - host wb_keygen, and prove the white-box is standard AES-128 --------------
step 1 "$TOTAL" "Phase 1 - host wb_keygen + FIPS-197 anchor"

# On Linux, link wb_keygen STATICALLY. This is the one artifact in the portable bundle that is a
# native host binary, and a dynamically linked one carries a glibc floor: the receiving machine
# is frequently a different distro from the builder, and the failure mode is
# `/lib64/libc.so.6: version GLIBC_2.xx not found` at FIRST PACK, on the machine least equipped
# to debug it. Static removes the question rather than managing it.
#
# gen_blob.sh deliberately refuses EXTRA_CXXFLAGS/EXTRA_LDFLAGS/ZIG_BIN so no cross toolchain can
# leak into a provisioning tool, but it does honour HOST_CXX/HOST_AR - so a wrapper is the only
# seam, and it is the intended one. `-static` is accepted-and-ignored on the compile-only
# libsodium TUs, so one wrapper covers both uses.
#
# Not done on macOS: Apple does not ship a crt0.o for static linking and `ld -static` is
# unsupported there. The macOS equivalent is gate 4 of artifact_generation.sh, which requires
# every dylib to come from /usr/lib or /System.
if [ "$(uname -s)" = "Linux" ] && [ -z "${HOST_CXX:-}" ]; then
    # `if` rather than `have "$c" && ... && break`: that form leaves the LOOP's exit status at 1
    # when nothing matches, and under `set -e` a bare compound command failing kills the script
    # silently - right here, before the die below could explain anything. Same trap as
    # find_sodium_inc in Phase 3, which carries the long version of this note.
    HOST_CXX_BASE=""
    for c in c++ g++ clang++; do
        if have "$c"; then HOST_CXX_BASE="$(command -v "$c")"; break; fi
    done
    [ -n "$HOST_CXX_BASE" ] || die "no host C++ compiler (c++/g++/clang++) on PATH"
    # A STABLE path, not $TMP. gen_blob.sh keys its libsodium cache on "$CXX|$AR|$(uname -sm)",
    # so a wrapper at a fresh mktemp path every run would invalidate that cache every run and
    # rebuild ~120 translation units for nothing.
    mkdir -p "$WBC/build-host"
    STATIC_CXX="$WBC/build-host/.sopack-static-c++"
    cat >"$STATIC_CXX" <<EOF
#!/bin/sh
exec "$HOST_CXX_BASE" "\$@" -static -static-libstdc++ -static-libgcc
EOF
    chmod +x "$STATIC_CXX"
    export HOST_CXX="$STATIC_CXX"
    info "linking wb_keygen statically via $HOST_CXX_BASE (portable across Linux distros)"
elif [ -n "${HOST_CXX:-}" ]; then
    warn "HOST_CXX=$HOST_CXX is set, so wb_keygen is built with it as-is. On Linux the bundle
      gate requires a STATIC keygen (no DT_NEEDED); unset HOST_CXX to get one automatically."
fi

HOST_KEYGEN="$WBC/build-host/wb_keygen"
# Cache invalidation, not a gate. build-host/ is gitignored and therefore travels with any copy
# or bind mount of the tree, so three kinds of wrong thing land there: a MACH-O keygen from a
# checkout copied off a Mac, a keygen built before the static wrapper existed, and - the nastiest
# - one built for a DIFFERENT ARCHITECTURE from a container sharing the same checkout.
#
# The architecture case is why this checks e_machine and not just "does it run". Docker Desktop on
# Apple Silicon runs a linux/amd64 container on an aarch64 kernel, so a leftover aarch64 keygen
# executes fine there while `uname -m` says x86_64: every probe passes and the bundle ships a
# keygen that is dead on the real x86_64 target. It also poisons Phase 3, because skipping
# gen_blob.sh leaves the equally stale build-host/libsodium.a in place and the probe link fails
# with "Relocations in generic ELF (EM: 183)".
#
# Rebuilding is the whole fix: gen_blob.sh keys its own libsodium cache on "$(uname -sm)", so once
# it runs again the archive is rebuilt for this host too.
if [ "$(uname -s)" = "Linux" ] && [ -x "$HOST_KEYGEN" ] && [ "$FORCE" -eq 0 ] \
   && [ -n "${STATIC_CXX:-}" ]; then
    STALE=""
    KEYGEN_EM="$(elf_machine "$HOST_KEYGEN")"
    WANT_EM="$(host_elf_machine)"
    if [ -z "$KEYGEN_EM" ]; then
        STALE="not an ELF (a macOS build, most likely, from a copied checkout)"
    elif [ -n "$WANT_EM" ] && [ "$KEYGEN_EM" != "$WANT_EM" ]; then
        STALE="built for $(elf_machine_name "$KEYGEN_EM"), but this host is
      $(elf_machine_name "$WANT_EM") - a checkout shared with a container or machine of another
      architecture"
    elif [ -n "$(elf_needed "$HOST_KEYGEN")" ]; then
        STALE="dynamically linked, so it would carry a glibc floor to the target machine"
    fi
    if [ -n "$STALE" ]; then
        info "cached $HOST_KEYGEN is $STALE - rebuilding"
        rm -f "$HOST_KEYGEN"
        # The archive is stale for exactly the same reason and is what Phase 3 links against.
        # gen_blob.sh would rebuild it via its own stamp, but only on the arch change - drop it
        # here so the static-linkage case is covered too.
        rm -f "$WBC/build-host/libsodium.a" "$WBC/build-host/.sodium-cc"
    fi
fi
if [ -x "$HOST_KEYGEN" ] && [ "$FORCE" -eq 0 ]; then
    info "reusing $HOST_KEYGEN (use --force to rebuild)"
else
    # gen_blob.sh, NOT the similarly-named scripts/build_host.sh. Upstream ships both and they
    # are different tools: build_host.sh builds WBC's tests and CLI tools into build/ and
    # honours ZIG_BIN/EXTRA_CXXFLAGS, so it can hand you a cross-built or O-MVLL-obfuscated
    # wb_keygen that does not run here. gen_blob.sh refuses both, picks a native compiler, and
    # writes build-host/wb_keygen - which upstream's own header calls "part of the consumer
    # contract" with this repo, by name. Do not switch this to build_host.sh.
    info "building the host provisioning tool via scripts/gen_blob.sh …"
    if ! ( cd "$WBC" && bash scripts/gen_blob.sh \
             --key 000102030405060708090a0b0c0d0e0f --pass demo --seed 42 \
             --out "$TMP/sealed.blob" ) >"$TMP/genblob.log" 2>&1; then
        if grep -q "'abort' is not a member of 'std'" "$TMP/genblob.log"; then
            die "your whitebox-cryptography checkout predates the '#include <cstdlib>' fix in
       src/vm/assembler.cpp, so gen_blob.sh cannot build on this host. Update it."
        fi
        tail -30 "$TMP/genblob.log" >&2
        die "gen_blob.sh failed (full log: $TMP/genblob.log - kept only until this script exits)"
    fi
    grep -q "$FIPS_VECTOR" "$TMP/genblob.log" \
        || { tail -20 "$TMP/genblob.log" >&2
             die "gen_blob.sh did not print the FIPS-197 vector $FIPS_VECTOR - the white-box is
       not behaving as standard AES-128, which the whole key-wrap design relies on"; }
    ok "FIPS-197 anchor $FIPS_VECTOR - the white-box is bit-exact AES-128"
fi
[ -x "$HOST_KEYGEN" ] || die "expected a host tool at $HOST_KEYGEN after gen_blob.sh"
# A CAPABILITY probe, not an existence check, and it runs on the CACHED path too - which is the
# whole point. The branch above reuses $HOST_KEYGEN whenever it exists, so a user who updates
# $WBC to 3.0.0 and re-runs without --force otherwise keeps a pre-3.0.0 keygen and only finds
# out on device. It must also run HERE at all: an Android build cannot.
"$HOST_KEYGEN" >/dev/null 2>&1 || true      # no args => usage, exit 2; we only care that it execs
if ! "$HOST_KEYGEN" --key 000102030405060708090a0b0c0d0e0f --pass p --seed 1 \
        --kdf light --out "$TMP/probe.blob" >"$TMP/probe.log" 2>&1; then
    if grep -qE -- '--kdf|unknown arg' "$TMP/probe.log"; then
        die "$HOST_KEYGEN is a STALE PRE-3.0.0 host wb_keygen: it rejects --kdf. sopack seals
       at the light KDF tier and requires >= 3.0.0. It was almost certainly REUSED from an
       earlier run (this phase caches it) - re-run with --force, or rebuild it by hand:
           cd $WBC && bash scripts/gen_blob.sh --key 000102030405060708090a0b0c0d0e0f \\
               --pass demo --seed 42 --kdf light --out /tmp/sealed.blob"
    fi
    tail -5 "$TMP/probe.log" >&2
    die "$HOST_KEYGEN does not run on this host (an Android build cannot) - rebuild with
       $WBC/scripts/gen_blob.sh"
fi
# Verify the blob it produced really is v>=4 at tier 0, through the SAME parser the packer
# uses - two copies of these offsets would drift.
( cd "$SOPACK" && python3 -c '
import sys
from sopack.provision import assert_light_blob, blob_header
blob = open(sys.argv[1], "rb").read()
assert_light_blob(blob, tool=sys.argv[2])
print("    blob header: magic=%s version=%d tier=%d" % blob_header(blob))
' "$TMP/probe.blob" "$HOST_KEYGEN" ) \
    || die "$HOST_KEYGEN accepted --kdf but did not produce a v4 light-tier blob (above).
       That is a 3.0.0-or-newer tool behaving unexpectedly - do not pack with it."
# Copy it where sopack looks for it unaided. provision.find_wb_keygen probes
# vendor/wbc/bin/wb_keygen FIRST, so from here on `sopack pack` needs no flag, no config key and no
# $SOPACK_WBKEYGEN - which is why this script no longer exports one. `install -m 0755` rather
# than cp: the exec bit is the whole point, and a plain cp inherits the source's mode only by
# luck.
mkdir -p "$SOPACK/vendor/wbc/bin"
install -m 0755 "$HOST_KEYGEN" "$SOPACK/vendor/wbc/bin/wb_keygen" \
    || die "could not copy $HOST_KEYGEN into $SOPACK/vendor/wbc/bin/"
ok "host wb_keygen usable and honours --kdf light -> vendor/wbc/bin/wb_keygen"

# ---- Phase 2 - unit tests --------------------------------------------------------------
step 2 "$TOTAL" "Phase 2 - sopack unit tests"
if [ "$SKIP_TESTS" -eq 1 ]; then
    warn "skipped by --skip-tests"
else
    ( cd "$SOPACK" && python3 -m pytest tests/ -q ) \
        || die "unit tests failed - fix these before trusting anything below"
    ok "unit tests pass (vendor/wbc/bin/wb_keygen exists, so the full-injection tests run too)"
fi

# ---- Phase 3 - full round-trip through the REAL white-box ------------------------------
step 3 "$TOTAL" "Phase 3 - host round-trip through the real white-box"
# Globbed HERE, not in preflight, and this ordering is load-bearing. libsodium is not committed
# in WBC - it is fetched by its third_party/fetch_deps.sh, which Phase 1's gen_blob.sh runs. A
# preflight glob therefore comes up empty on every freshly-initialised submodule and this phase
# would die telling you to run the fetcher that Phase 1 just ran.
#
# And Phase 1 is not a guarantee either: its cache branch skips gen_blob.sh entirely when
# build-host/wb_keygen already exists, so a tree with a cached keygen and no libsodium reaches
# here with nothing fetched. Hence the fetch below - it is idempotent (.vendored-ok stamp), so
# it costs nothing on a warm tree and makes this phase self-sufficient either way.
#
# `return 0` is NOT decoration. When the glob matches nothing, `[ -f … ] && SODIUM_INC=…`
# returns 1, so the for-loop returns 1 and so does the function - and under `set -e` a bare
# call to it kills the script SILENTLY, right after the step header, with no error and no
# clue. "libsodium is absent" is exactly the case this function exists to detect, so the
# not-found path must be an ordinary return, not a fatal one.
find_sodium_inc() {
    SODIUM_INC=""
    for d in "$WBC"/third_party/libsodium/libsodium-*/src/libsodium/include; do
        [ -f "$d/sodium.h" ] && SODIUM_INC="$d"
    done
    return 0
}
find_sodium_inc
if [ -z "$SODIUM_INC" ]; then
    info "vendoring libsodium into $WBC/third_party (fetch_deps.sh; needs network once) …"
    ( cd "$WBC" && ./third_party/fetch_deps.sh libsodium ) >"$TMP/fetchdeps.log" 2>&1 \
        || { tail -20 "$TMP/fetchdeps.log" >&2
             die "$WBC/third_party/fetch_deps.sh libsodium failed (above)"; }
    find_sodium_inc
fi
[ -n "$SODIUM_INC" ] || die "no vendored libsodium headers under $WBC/third_party/libsodium
       even after running $WBC/third_party/fetch_deps.sh libsodium"
[ -f "$WBC/build-host/libsodium.a" ] || die "no $WBC/build-host/libsodium.a - Phase 1 builds it
       as a side effect of gen_blob.sh; re-run with --force"

info "building the round-trip probe …"
cc -O2 -I"$WBC/include" -I"$SOPACK/stub" -c "$HERE/rt_roundtrip.c" -o "$TMP/rt_roundtrip.o" \
    || die "probe compile failed"
# The provisioning sources (src/tools, src/rt) are deliberately excluded, matching the doc.
PROBE_SRCS=""
for f in $(cd "$WBC" && find src -name '*.cpp' -not -path 'src/tools/*' -not -path 'src/rt/*' \
           | sort); do
    PROBE_SRCS="$PROBE_SRCS $WBC/$f"
done
# shellcheck disable=SC2086
c++ -std=c++17 -O2 -w -I"$WBC/src" -I"$WBC/include" -I"$SODIUM_INC" \
    "$TMP/rt_roundtrip.o" $PROBE_SRCS "$WBC/build-host/libsodium.a" -o "$TMP/rt_roundtrip" \
    || die "probe link failed"

info "provisioning a 5.5 MB payload through the real packer code …"
( cd "$SOPACK" && python3 - "$TMP" <<'PY'
import os, sys
from sopack.provision import provision_pack, provision_text
from sopack.rt_meta import TargetRegion, WbRegion
tmp = sys.argv[1]
plain = os.urandom(5_513_872)                  # libapp.so-sized .text
pack = provision_pack()                        # ONE sealed kek for the whole (pack, ABI)
prov = provision_text(plain, pack)              # wraps a per-target session key, encrypts
# Two regions since v3, mirroring the two shipped artifacts: the provider carries the single
# blob + passphrase, the target region carries only its own wrapped key.
wbregion = WbRegion(wpass=pack.wpass, blob=pack.blob).pack()
region = TargetRegion(text_rva=0x10000, text_size=len(plain), wrapped=prov.wrapped,
                      nonce16=prov.nonce16, soname=b'libapp.so').pack()
open(os.path.join(tmp, 'wbregion.bin'), 'wb').write(wbregion)
open(os.path.join(tmp, 'region.bin'), 'wb').write(region)
open(os.path.join(tmp, 'cipher.bin'), 'wb').write(prov.ciphertext)
open(os.path.join(tmp, 'plain.bin'), 'wb').write(plain)
print(f'    provisioned {len(plain)} bytes; target region {len(region)} '
      f'(no blob), provider region {len(wbregion)}, blob {len(pack.blob)}')
PY
) || die "provisioning failed"

"$TMP/rt_roundtrip" "$TMP/wbregion.bin" "$TMP/region.bin" "$TMP/cipher.bin" "$TMP/plain.bin" \
    || die "round-trip FAILED - a Python<->C contract has drifted; the probe names which one"
ok "round-trip PASS - both region layouts, whitening, key wrap and ChaCha20 all agree"

# ---- Phase 4 - the Android runtime lib and the helper skeleton --------------------------
if [ "$HOST_ONLY" -eq 1 ]; then
    cat <<EOF

==> Host phases 1-3 PASS (--host-only). Every Python<->C contract agrees: the region layout,
    the passphrase whitening, the key wrap and the ChaCha20 mirror.

    No helper skeleton was built, so you cannot pack yet. Re-run without --host-only, with an
    NDK available, to do Phase 4.
EOF
    exit 0
fi

step 4 "$TOTAL" "Phase 4 - Android libwbcrypto.a + helper skeleton"
ANDROID_LIB="$WBC/build-android/libwbcrypto.a"
if [ -f "$ANDROID_LIB" ] && [ "$FORCE" -eq 0 ]; then
    info "reusing $ANDROID_LIB (use --force to rebuild)"
    # An archive carries no record of whether O-MVLL ran, so this branch cannot tell an
    # obfuscated cache from a --no-omvll one. Say so rather than implying the default held.
    [ "$OMVLL" -eq 1 ] && warn "the cached archive may predate --omvll becoming the default; an
      .a records no obfuscation state, so re-run with --force if this is a release build"
else
    # build_android.sh defaults to O-MVLL ON and fetches/configures the plugin itself, so the
    # obfuscated build is "pass nothing". Preflight already refused --omvll on a non-Darwin host.
    OMVLL_ARG=""
    [ "$OMVLL" -eq 0 ] && OMVLL_ARG="--no-omvll"

    # Can clang actually LOAD the plugin? Ask the dynamic linker before handing 155 translation
    # units to ninja. clang reports an unloadable plugin per-TU, so the real failure - one line
    # about a missing symbol or glibc version - arrives buried in ten identical multi-line
    # walls. The known instance: the O-MVLL 1.9.1 Linux plugin requires GLIBC_2.38, so it will
    # not load on Debian bookworm (2.36); the shipped image uses ubuntu:24.04 for that reason.
    # Only checkable when the plugin is already vendored - build_android.sh fetches it otherwise,
    # and skipping the check then is fine because a fresh fetch is not the interesting case.
    OMVLL_PLUGIN="$WBC/third_party/omvll/omvll_ndk_r29.so"
    if [ "$OMVLL" -eq 1 ] && [ "$(uname -s)" = "Linux" ] && [ -f "$OMVLL_PLUGIN" ] && have ldd; then
        LDD_OUT="$(ldd "$OMVLL_PLUGIN" 2>&1 || true)"
        case "$LDD_OUT" in
            *"not found"*)
                printf '%s\n' "$LDD_OUT" | grep -F 'not found' >&2
                die "the O-MVLL plugin cannot be loaded on this host (details above). clang would
       report this once per translation unit, which is why it is checked here.
       If it names a GLIBC_ version, this host's glibc is older than the plugin was built
       against ($(ldd --version | head -1)); build on a newer base - docker/Dockerfile uses
       ubuntu:24.04 for exactly this. Otherwise pass --no-omvll (and, for a bundle,
       --allow-unobfuscated-provider) to build without obfuscation." ;;
        esac
        ok "the O-MVLL plugin's dynamic dependencies resolve on this host"
    fi

    info "cross-building the runtime library (${OMVLL_ARG:---omvll}) …"
    # shellcheck disable=SC2086
    ( cd "$WBC" && NDK="$NDK" ./scripts/build_android.sh --abi "$ABI" --api "$API" $OMVLL_ARG ) \
        || die "scripts/build_android.sh failed"
fi
[ -f "$ANDROID_LIB" ] || die "expected $ANDROID_LIB after build_android.sh"

# BEFORE the copy, not after. The branch above reuses a cached build-android/libwbcrypto.a, but
# the cp below takes the FRESH $WBC/include/wbcrypto.h - so a stale cache pairs a 3.0.0 header
# with a pre-3.0.0 archive in vendor/wbc/. sopk_rt.c then COMPILES and the link fails, which is
# a confusing place to discover it. Check the archive itself, here.
if [ -x "$NDKBIN/llvm-nm" ]; then
    ARCHIVE_SYMS="$("$NDKBIN/llvm-nm" --defined-only "$ANDROID_LIB" 2>/dev/null || true)"
else
    ARCHIVE_SYMS="$(cat "$ANDROID_LIB")"        # symbol names appear literally in the archive
fi
case "$ARCHIVE_SYMS" in
    *wbc_blob_kdf_tier*) ;;
    *) die "$ANDROID_LIB defines no wbc_blob_kdf_tier, so it is a PRE-3.0.0 archive - almost
       certainly the CACHED one from an earlier run (this phase reuses build-android/). Copying
       it into vendor/wbc/ next to a 3.0.0 wbcrypto.h pairs a new header with an old archive:
       stub/sopk_rt.c compiles and the LINK then fails on wbc_blob_kdf_tier. Re-run with
       --force." ;;
esac
ok "$(basename "$ANDROID_LIB") is a 3.0.0 archive (defines wbc_blob_kdf_tier)"

mkdir -p "$SOPACK/vendor/wbc"
cp "$ANDROID_LIB" "$WBC/include/wbcrypto.h" "$SOPACK/vendor/wbc/"
ok "vendor/wbc/ refreshed from $WBC/build-android"

SKEL="$SOPACK/sopack/stubs/sopk_rt_$ABI.so"
PROV="$SOPACK/sopack/stubs/sopk_wb_$ABI.so"
PROV_SONAME="libsopk_wb.so"
mkdir -p "$(dirname "$SKEL")"
TRACE_FLAGS=""
[ "$RELEASE" -eq 0 ] && TRACE_FLAGS="-DSOPK_RT_LOG -llog"

# TWO artifacts since region v3, and they must be built in this order - 4b links against 4a's
# output, so no single invocation can produce both:
#
#   4a  sopk_wb.c  -> libsopk_wb.so   ONE per ABI. Links libwbcrypto.a; owns every wbc_* call
#                                     and the sealed blob. Exports exactly sopk_wb_k.
#   4b  sopk_rt.c  -> sopk_rt_<abi>.so  the THIN per-target helper. Links NO white-box; the
#                                     packer clones it per target.
#
# clang++ (not clang: the archive is C++) and libc++ STATIC for 4a - a libc++_shared.so
# dependency would be another .so to ship and the packer rejects it. -x c because both sources
# are C. --no-undefined so a pre-3.0.0 archive fails HERE instead of on device.
#
# -Wl,-soname on 4a is LOAD-BEARING, not tidiness: the thin helper's DT_NEEDED string is whatever
# the linker recorded as the provider's DT_SONAME, and without an explicit soname lld records the
# PATH it was given (".../sopack/stubs/sopk_wb_arm64-v8a.so"), producing an APK that cannot load.
# The packer asserts DT_SONAME == libsopk_wb.so rather than fixing it, because it cannot fix it.
#
# -g0 and -ffile-prefix-map are load-bearing for static-analysis resistance: a default build
# carries ~2.7 MB of DWARF naming every function (sopk_rt_ctor, the wbc_* API, the VM handlers)
# plus absolute host source paths, which leak a developer username and pin the vendored libsodium
# version. The packer strips what it can at pack time, but doing it here keeps the artifact
# honest. Note -ffile-prefix-map only rewrites paths for THESE files; strings baked into
# libwbcrypto.a need the same flag in the whitebox-cryptography build.
link_provider() {   # link_provider <extra flags…>
    # shellcheck disable=SC2086
    "$CXX" --target="${ABI_TRIPLE}${API}" -fPIC -shared -O2 -g0 \
        -ffile-prefix-map="$WBC=." -ffile-prefix-map="$SOPACK=." \
        -fvisibility=hidden -Wl,--exclude-libs,ALL -Wl,--no-undefined \
        -Wl,-soname,"$PROV_SONAME" \
        "$@" \
        -I"$WBC/include" -I"$SOPACK/stub" \
        -x c "$SOPACK/stub/sopk_wb.c" -x none \
        "$SOPACK/vendor/wbc/libwbcrypto.a" \
        $TRACE_FLAGS \
        -o "$PROV" 2>"$TMP/link.log"
}

info "linking the shared white-box provider (4a) …"
if ! link_provider -static-libstdc++; then
    if grep -qi "static-libstdc++\|unsupported option" "$TMP/link.log"; then
        warn "-static-libstdc++ not accepted; retrying with the explicit libc++ archives"
        SYSROOT="$NDK/toolchains/llvm/prebuilt/$HOSTTAG/sysroot"
        LIBDIR="$SYSROOT/usr/lib/${ABI_TRIPLE%%-*}-linux-android"
        [ -d "$LIBDIR" ] || LIBDIR="$SYSROOT/usr/lib/$ABI_TRIPLE"
        link_provider "$LIBDIR/libc++_static.a" "$LIBDIR/libc++abi.a" \
            || { cat "$TMP/link.log" >&2; die "provider link failed"; }
    else
        cat "$TMP/link.log" >&2
        if grep -q "undefined reference to \`wbc_" "$TMP/link.log"; then
            die "the archive in vendor/wbc/ is missing symbols sopk_wb.c needs, i.e. it is
       PRE-3.0.0. Note sopk_wb.c COMPILED, so the header is 3.0.0 and only the archive is
       stale - the classic cached-build-android/ pairing. --no-undefined caught it here
       instead of on device. Re-run with --force."
        fi
        die "provider link failed (log above)"
    fi
fi
"$NDKBIN/llvm-strip" --strip-all "$PROV" 2>/dev/null || true
ok "provider: $(basename "$PROV") ($(wc -c <"$PROV" | tr -d ' ') bytes)"

# 4b: the thin helper. Simpler than the provider's link - plain clang, no static libc++, no
# libwbcrypto.a - but it MUST take the provider as a link input so --no-undefined still holds and
# the DT_NEEDED comes from the provider's DT_SONAME rather than being invented.
link_skeleton() {   # link_skeleton <extra flags…>
    # shellcheck disable=SC2086
    "$NDKBIN/clang" --target="${ABI_TRIPLE}${API}" -fPIC -shared -O2 -g0 \
        -ffile-prefix-map="$SOPACK=." \
        -fvisibility=hidden -Wl,--no-undefined \
        "$@" \
        -I"$SOPACK/stub" \
        "$SOPACK/stub/sopk_rt.c" \
        "$PROV" \
        $TRACE_FLAGS \
        -o "$SKEL" 2>"$TMP/link.log"
}

info "linking the thin helper skeleton (4b) …"
if ! link_skeleton; then
    cat "$TMP/link.log" >&2
    if grep -q "undefined reference to \`wbc_" "$TMP/link.log"; then
        die "sopk_rt.c references white-box symbols, which it must NOT do since the v3 split -
       every wbc_* call lives in stub/sopk_wb.c now. Either stub/sopk_rt.c is stale (pre-v3) or
       it is being compiled with the wrong source."
    fi
    if grep -q "undefined reference to \`sopk_wb_k" "$TMP/link.log"; then
        die "the thin helper cannot resolve sopk_wb_k against $PROV. The provider linked but did
       not EXPORT its entry point - check that stub/sopk_wb.c still marks sopk_wb_k
       __attribute__((visibility(\"default\"))), since the link uses -fvisibility=hidden."
    fi
    die "thin helper link failed (log above)"
fi
ok "skeleton built: $SKEL"

# -g0 stops OUR debug info; the static archive still contributes its own symbols, so strip.
# --strip-all removes .symtab/.strtab/.comment and any remaining .debug_*, and keeps .dynsym /
# .dynstr / the section header table - which is what bionic needs. This is NOT the section-header
# stripping that docs/technical/HARDENING.md §Method 3 rejected (that zeroed e_shoff).
STRIP="$(dirname "$CXX")/llvm-strip"
if [ -x "$STRIP" ]; then
    before=$(wc -c <"$SKEL")
    "$STRIP" --strip-all "$SKEL" || die "llvm-strip failed on $SKEL"
    ok "stripped: $before -> $(wc -c <"$SKEL") bytes"
else
    warn "llvm-strip not found at $STRIP; the packer will strip at pack time instead"
fi

# ---- Phase 4 PASS checks ---------------------------------------------------------------
# Per artifact, because the expectations DIFFER: the provider must export exactly one symbol and
# define every wbc_*, while the thin helper must export nothing and reference no wbc_* at all.
needed_of() { "$READELF" -dW "$1" | awk '/NEEDED/ {gsub(/[][]/,"",$5); print $5}'; }
exports_of() { "$READELF" --dyn-syms "$1" \
    | awk '($5=="GLOBAL"||$5=="WEAK") && $7!="UND" && $8!="" {print $8}' | sort -u; }
undef_of() { "$READELF" --dyn-syms "$1" | awk '$7=="UND" && $8!="" {print $8}' | sort -u; }

info "checking the provider …"
BAD_NEEDED=""
for n in $(needed_of "$PROV"); do
    case "$n" in
        libc.so|libm.so|libdl.so|liblog.so) ;;
        *) BAD_NEEDED="$BAD_NEEDED $n" ;;
    esac
done
if [ -n "$BAD_NEEDED" ]; then
    case "$BAD_NEEDED" in
        *libc++_shared.so*) die "provider depends on libc++_shared.so - the static libc++ did not
       take effect. It must be statically linked, or the packer will reject the skeleton." ;;
    esac
    die "provider has non-bionic DT_NEEDED:$BAD_NEEDED - something was not statically linked"
fi
ok "provider DT_NEEDED is bionic-only:$(printf ' %s' $(needed_of "$PROV"))"

# The DT_SONAME is what every thin helper records as its DT_NEEDED, so it is checked, never fixed.
PROV_HAS_SONAME="$("$READELF" -dW "$PROV" | awk '/SONAME/ {gsub(/[][]/,"",$5); print $5}')"
[ "$PROV_HAS_SONAME" = "$PROV_SONAME" ] || die "provider DT_SONAME is '$PROV_HAS_SONAME',
       expected '$PROV_SONAME'. Without -Wl,-soname the linker records the file PATH, which the
       thin helper then hard-codes as its DT_NEEDED - an APK that cannot load. The packer refuses
       this rather than renaming it, because renaming would break every helper already linked."
ok "provider DT_SONAME is $PROV_SONAME"

PROV_EXPORTS="$(exports_of "$PROV")"
if [ "$PROV_EXPORTS" != "sopk_wb_k" ]; then
    printf '%s\n' "$PROV_EXPORTS" | sed 's/^/      /' >&2
    die "provider must export EXACTLY sopk_wb_k, no more and no fewer (got the above). Nothing
       means -Wl,--exclude-libs,ALL or a '{ local: *; };' version script swallowed the entry -
       it needs __attribute__((visibility(\"default\"))), which stub/sopk_wb.c has. Extra names
       mean --exclude-libs did not take effect; if it will not, use a version script that keeps
       the entry:  printf '{ global: sopk_wb_k; local: *; };\\n' > /tmp/prov.map"
fi
ok "provider exports exactly sopk_wb_k"

PROV_IMPORTS="$(undef_of "$PROV" | grep -E '^(wbc_|sodium_)' || true)"
if [ -n "$PROV_IMPORTS" ]; then
    printf '%s\n' "$PROV_IMPORTS" | sed 's/^/      /' >&2
    die "provider IMPORTS the symbols above instead of defining them - it linked against a
       PRE-3.0.0 libwbcrypto.a. bionic could not load it, and every thin helper (and their
       targets) would fail to load with it."
fi
ok "provider imports no wbc_*/sodium_* (so it will load)"

info "checking the thin helper …"
BAD_NEEDED=""
for n in $(needed_of "$SKEL"); do
    case "$n" in
        libc.so|libm.so|libdl.so|liblog.so|"$PROV_SONAME") ;;
        *) BAD_NEEDED="$BAD_NEEDED $n" ;;
    esac
done
if [ -n "$BAD_NEEDED" ]; then
    case "$BAD_NEEDED" in
        *libc++_shared.so*) die "thin helper depends on libc++_shared.so - it should not link the
       C++ white-box at all since the v3 split. Is it being built from stub/sopk_wb.c?" ;;
    esac
    die "thin helper has unexpected DT_NEEDED:$BAD_NEEDED (bionic + $PROV_SONAME only)"
fi
# POSITIVE containment: a helper that lost the dependency fails on device as "cannot locate
# symbol sopk_wb_k", taking the target's dlopen with it, nowhere near the cause.
needed_of "$SKEL" | grep -qx "$PROV_SONAME" || die "thin helper does not DT_NEEDED $PROV_SONAME -
       it was linked without $PROV as an input, so it cannot obtain a session key."
ok "thin helper DT_NEEDED is bionic + $PROV_SONAME"

SKEL_EXPORTS="$(exports_of "$SKEL")"
if [ -n "$SKEL_EXPORTS" ]; then
    printf '%s\n' "$SKEL_EXPORTS" | sed 's/^/      /' >&2
    die "thin helper EXPORTS the symbols above; it should export nothing. Add a version script:
       printf '{ local: *; };\\n' > /tmp/hide-all.map
       then add -Wl,--version-script=/tmp/hide-all.map to the 4b link line."
fi
ok "thin helper exports nothing"

SKEL_UNDEF="$(undef_of "$SKEL")"
SKEL_WB="$(printf '%s\n' "$SKEL_UNDEF" | grep -E '^(wbc_|sodium_)' || true)"
if [ -n "$SKEL_WB" ]; then
    printf '%s\n' "$SKEL_WB" | sed 's/^/      /' >&2
    die "thin helper references the white-box symbols above. Since the v3 split ONLY
       $PROV_SONAME may touch the white-box; the thin helper calls sopk_wb_k instead. It was
       probably built from stub/sopk_wb.c, or linked libwbcrypto.a by mistake."
fi
printf '%s\n' "$SKEL_UNDEF" | grep -qx "sopk_wb_k" || die "thin helper does not import
       sopk_wb_k, so its ctor could not obtain a session key. Rebuild it from stub/sopk_rt.c."
ok "thin helper imports sopk_wb_k and no wbc_*/sodium_*"

# Both markers, and they are DIFFERENT values on purpose: with one shared marker, a freshly
# built thin helper paired with a stale provider would pass both checks.
( cd "$SOPACK" && python3 - "$SKEL" "$PROV" <<'PY'
import sys
from sopack.rt_meta import HELPER_BUILD_MARKER, PROVIDER_BUILD_MARKER, REGION_VERSION
for path, marker, src in ((sys.argv[1], HELPER_BUILD_MARKER, 'stub/sopk_rt.c'),
                          (sys.argv[2], PROVIDER_BUILD_MARKER, 'stub/sopk_wb.c')):
    if marker not in open(path, 'rb').read():
        sys.exit(f"ERROR: {path} lacks the v{REGION_VERSION} build marker "
                 f"({marker.hex()}) - it was built from an older {src}. sopack would refuse "
                 "it at pack time.")
PY
) || exit 1
ok "both artifacts carry the build markers the packer greps for"

# The size split IS the point of the v3 provider design, so assert it rather than trusting it: the
# thin helper must no longer contain the ~465 KB white-box, or nothing was actually saved.
SKEL_SZ=$(wc -c <"$SKEL" | tr -d ' ')
PROV_SZ=$(wc -c <"$PROV" | tr -d ' ')
if [ "$SKEL_SZ" -gt 102400 ]; then
    die "the thin helper is $SKEL_SZ bytes - far too large. Since the v3 split it links no
       white-box, so it should be a few KB. It looks like it still statically links
       libwbcrypto.a, which would defeat the whole point (N copies of ~465 KB again)."
fi
ok "size split: thin helper $SKEL_SZ B, provider $PROV_SZ B (the provider ships ONCE per ABI)"

# ---- next step -------------------------------------------------------------------------
cat <<EOF

==> Host phases 1-4 PASS. Phase 5 is yours to run - it needs your APK and lib names:

  cd "$SOPACK"
  mkdir -p output
  python3 -m sopack.cli pack <your.apk> -o output/packed.apk

  The command line carries only the input and output APK. Everything else comes from
  ./config.yaml if you have one - and with no config at all the defaults are already right
  here: cipher wbaes, abis [$ABI], signature verification on, and every lib/$ABI/*.so in the
  APK selected. The keygen this phase just built is found at vendor/wbc/bin/wb_keygen; there
  is no flag and no config key for it.

  To narrow it to specific libraries, or point at your own keystore:

    python3 -m sopack.cli init-config       # writes ./config.yaml, fully commented
    #   libraries:
    #     include:
    #       - libfoo.so
    #       - libbar.so

Then verify the packed APK and go to device, per docs/technical/WBAES.md Phases 5-6.
EOF
if [ "$RELEASE" -eq 0 ]; then
    cat <<EOF

  This skeleton is a TRACING build, so the helper logs a per-phase timing line at load:
      adb logcat -s sopk_rt sopk_wb DEBUG   # sopk_wb = the shared provider's tag
  It also needs 'pack --allow-helper-log', because those same lines hand an attacker the
  .text address and length to dump. Re-run WITHOUT --trace before shipping.
EOF
else
    cat <<EOF

  This skeleton is a RELEASE build: no logcat output, so a failure at load is a SIGABRT
  with no message (by design - see the fail-closed note in stub/sopk_rt.c). If the app
  crashes on device, rebuild with --trace and pack with --allow-helper-log to find out why.
EOF
fi
