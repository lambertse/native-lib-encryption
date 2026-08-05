#!/usr/bin/env bash
#
# build_wbaes.sh — get `--cipher wbaes` from a clean checkout to a packable state, running
# Phases 1-4 of docs/wbaes-verification.md and every one of their PASS checks. It stops before
# packing (that needs YOUR APK and lib names) and prints the Phase-5 command to run next.
#
# Why a script: the failure modes of this mode are unforgiving and mostly SILENT. A 1.x
# libwbcrypto.a links cleanly and only breaks on device; a stale helper skeleton fails open and
# lets encrypted .text run; the wrong compiler driver leaves the whole C++ runtime unresolved.
# Each of those has cost a debugging session here, so each is a hard gate below.
#
# Usage:
#   ./scripts/build_wbaes.sh                          # prompts for WBC/NDK if unset
#   WBC=~/src/whitebox-cryptography NDK=~/ndk/29 ./scripts/build_wbaes.sh
#   ./scripts/build_wbaes.sh --wbc ~/src/wbc --ndk ~/ndk/29 --release
#
# Options:
#   --wbc PATH      whitebox-cryptography checkout (>= 2.0.0). Else $WBC, else prompt.
#   --ndk PATH      Android NDK root.               Else $NDK/$ANDROID_NDK_HOME/
#                   $ANDROID_NDK_ROOT, else prompt.
#   --abi ABI       default arm64-v8a
#   --api N         default 24
#   --release       build the skeleton WITHOUT -DSOPK_RT_LOG (no logcat tracing, no liblog).
#                   This is the DEFAULT — a tracing helper logs the target name, .text address
#                   and size to logcat, and `sopack pack` refuses to pack one.
#   --trace         opt into the tracing build for on-device Phase 6 verification. The result
#                   needs `sopack pack --allow-helper-log` and is NOT shippable.
#   --omvll         configure the Android build WITH the O-MVLL obfuscation plugin. Default is
#                   --no-omvll: fewer moving parts while proving the pipeline works.
#   --skip-tests    skip Phase 2 (the unit tests)
#   --host-only     run Phases 1-3 only and stop. Needs no NDK, no cmake and no ninja, so the
#                   Python<->C contracts can be verified on a machine that cannot cross-compile
#                   (CI, for instance). No skeleton is produced, so you cannot pack afterwards.
#   --force         redo cached phases (host wb_keygen, Android libwbcrypto.a)
#
# SOPACK is this script's own repo — never asked for.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOPACK="$(cd "$HERE/.." && pwd)"
# shellcheck source=scripts/_common.sh
. "$HERE/_common.sh"

ABI="arm64-v8a"
API=24
RELEASE=1
OMVLL=0
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
        --omvll)      OMVLL=1; shift ;;
        --skip-tests) SKIP_TESTS=1; shift ;;
        --host-only)  HOST_ONLY=1; shift ;;
        --force)      FORCE=1; shift ;;
        -h|--help)    sed -n '2,45p' "$0"; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

TMP="$(mktemp -d "${TMPDIR:-/tmp}/sopack-wbaes.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# ---- validators ------------------------------------------------------------------------
valid_wbc() {
    [ -d "$1" ] || { warn "$1 is not a directory"; return 1; }
    [ -f "$1/include/wbcrypto.h" ] || {
        warn "$1 has no include/wbcrypto.h — that is not a whitebox-cryptography checkout"
        return 1; }
    [ -f "$1/scripts/gen_blob.sh" ] || {
        warn "$1 has no scripts/gen_blob.sh — too old, or not the right repo"; return 1; }
    # The version gate that matters. 2.0.0 replaced the bulk API with key wrapping; a 1.x
    # header means stub/sopk_rt.c will not even compile, and a 1.x archive links SILENTLY.
    grep -q 'wbc_unwrap_key' "$1/include/wbcrypto.h" || {
        warn "$1/include/wbcrypto.h does not declare wbc_unwrap_key, so this checkout is"
        warn "pre-2.0.0. sopack requires >= 2.0.0 (key wrapping); update it and retry."
        return 1; }
    return 0
}

valid_ndk() {
    [ -d "$1" ] || { warn "$1 is not a directory"; return 1; }
    [ -f "$1/build/cmake/android.toolchain.cmake" ] || {
        warn "$1 has no build/cmake/android.toolchain.cmake — not an NDK root"; return 1; }
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
need cc  "the Phase 3 round-trip probe is C"
need c++ "libwbcrypto is C++"
if [ "$HOST_ONLY" -eq 0 ]; then
    need cmake "scripts/build_android.sh uses CMake (or pass --host-only)"
    need ninja "scripts/build_android.sh configures with -GNinja (or pass --host-only)"
fi
have openssl || warn "no openssl on PATH — the pack-side cipher falls back to pure Python
      (~0.6 MB/s), so packing a multi-MB .text will be slow but still correct"

( cd "$SOPACK" && python3 -c 'import sopack' >/dev/null 2>&1 ) \
    || die "cannot import sopack from $SOPACK — run: pip install -e ."

: "${NDK:=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
ask_path WBC "whitebox-cryptography checkout (>= 2.0.0): " valid_wbc \
    "Pass --wbc PATH or export WBC."

HOSTTAG="$(uname | tr '[:upper:]' '[:lower:]')-x86_64"
if [ "$HOST_ONLY" -eq 0 ]; then
    ask_path NDK "Android NDK root: " valid_ndk \
        "Pass --ndk PATH, export NDK / ANDROID_NDK_HOME, or run with --host-only."
    NDKBIN="$NDK/toolchains/llvm/prebuilt/$HOSTTAG/bin"
    [ -d "$NDKBIN" ] || die "no toolchain at $NDKBIN (host tag $HOSTTAG) — wrong NDK layout?"
    CXX="$NDKBIN/clang++"
    READELF="$NDKBIN/llvm-readelf"
    [ -x "$CXX" ] || die "no clang++ at $CXX"
    [ -x "$READELF" ] || die "no llvm-readelf at $READELF"
fi

SODIUM_INC=""
for d in "$WBC"/third_party/libsodium/libsodium-*/src/libsodium/include; do
    [ -f "$d/sodium.h" ] && SODIUM_INC="$d"
done

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
else warn "skeleton TRACING (-DSOPK_RT_LOG -llog) — needs 'pack --allow-helper-log'; NOT shippable"; fi

# ---- Phase 1 — host wb_keygen, and prove the white-box is standard AES-128 --------------
step 1 "$TOTAL" "Phase 1 — host wb_keygen + FIPS-197 anchor"
HOST_KEYGEN="$WBC/build-host/wb_keygen"
if [ -x "$HOST_KEYGEN" ] && [ "$FORCE" -eq 0 ]; then
    info "reusing $HOST_KEYGEN (use --force to rebuild)"
else
    info "building the host provisioning tool via scripts/gen_blob.sh …"
    if ! ( cd "$WBC" && bash scripts/gen_blob.sh \
             --key 000102030405060708090a0b0c0d0e0f --pass demo --seed 42 \
             --out "$TMP/sealed.blob" ) >"$TMP/genblob.log" 2>&1; then
        if grep -q "'abort' is not a member of 'std'" "$TMP/genblob.log"; then
            die "your whitebox-cryptography checkout predates the '#include <cstdlib>' fix in
       src/vm/assembler.cpp, so gen_blob.sh cannot build on this host. Update it."
        fi
        tail -30 "$TMP/genblob.log" >&2
        die "gen_blob.sh failed (full log: $TMP/genblob.log — kept only until this script exits)"
    fi
    grep -q "$FIPS_VECTOR" "$TMP/genblob.log" \
        || { tail -20 "$TMP/genblob.log" >&2
             die "gen_blob.sh did not print the FIPS-197 vector $FIPS_VECTOR — the white-box is
       not behaving as standard AES-128, which the whole key-wrap design relies on"; }
    ok "FIPS-197 anchor $FIPS_VECTOR — the white-box is bit-exact AES-128"
fi
[ -x "$HOST_KEYGEN" ] || die "expected a host tool at $HOST_KEYGEN after gen_blob.sh"
# It must run HERE: the shipped assets/wbc/wb_keygen is an Android build and cannot.
"$HOST_KEYGEN" >/dev/null 2>&1 || true      # no args => usage, exit 2; we only care that it execs
if ! "$HOST_KEYGEN" --key 000102030405060708090a0b0c0d0e0f --pass p --seed 1 \
        --out "$TMP/probe.blob" >/dev/null 2>&1; then
    die "$HOST_KEYGEN does not run on this host (an Android build cannot) — rebuild with
       $WBC/scripts/gen_blob.sh"
fi
export SOPACK_WBKEYGEN="$HOST_KEYGEN"
ok "host wb_keygen usable: $SOPACK_WBKEYGEN"

# ---- Phase 2 — unit tests --------------------------------------------------------------
step 2 "$TOTAL" "Phase 2 — sopack unit tests"
if [ "$SKIP_TESTS" -eq 1 ]; then
    warn "skipped by --skip-tests"
else
    ( cd "$SOPACK" && python3 -m pytest tests/ -q ) \
        || die "unit tests failed — fix these before trusting anything below"
    ok "unit tests pass (with SOPACK_WBKEYGEN set, the full-injection tests run too)"
fi

# ---- Phase 3 — full round-trip through the REAL white-box ------------------------------
step 3 "$TOTAL" "Phase 3 — host round-trip through the real white-box"
[ -n "$SODIUM_INC" ] || die "no vendored libsodium headers under $WBC/third_party/libsodium —
       run $WBC/third_party/fetch_deps.sh libsodium"
[ -f "$WBC/build-host/libsodium.a" ] || die "no $WBC/build-host/libsodium.a — Phase 1 builds it;
       re-run with --force"

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
from sopack.provision import provision_text
from sopack.rt_meta import Region
tmp = sys.argv[1]
plain = os.urandom(5_513_872)                  # libapp.so-sized .text
prov = provision_text(plain)                   # seals a kek, wraps a session key, encrypts
region = Region(text_rva=0x10000, text_size=len(plain), wrapped=prov.wrapped,
                nonce16=prov.nonce16, soname=b'libapp.so', wpass=prov.wpass,
                blob=prov.blob).pack()
open(os.path.join(tmp, 'region.bin'), 'wb').write(region)
open(os.path.join(tmp, 'cipher.bin'), 'wb').write(prov.ciphertext)
open(os.path.join(tmp, 'plain.bin'), 'wb').write(plain)
print(f'    provisioned {len(plain)} bytes; region {len(region)}, blob {len(prov.blob)}')
PY
) || die "provisioning failed"

"$TMP/rt_roundtrip" "$TMP/region.bin" "$TMP/cipher.bin" "$TMP/plain.bin" \
    || die "round-trip FAILED — a Python<->C contract has drifted; the probe names which one"
ok "round-trip PASS — region layout, whitening, key wrap and ChaCha20 all agree"

# ---- Phase 4 — the Android runtime lib and the helper skeleton --------------------------
if [ "$HOST_ONLY" -eq 1 ]; then
    cat <<EOF

==> Host phases 1-3 PASS (--host-only). Every Python<->C contract agrees: the region layout,
    the passphrase whitening, the key wrap and the ChaCha20 mirror.

    No helper skeleton was built, so you cannot pack yet. Re-run without --host-only, with an
    NDK available, to do Phase 4.
EOF
    exit 0
fi

step 4 "$TOTAL" "Phase 4 — Android libwbcrypto.a + helper skeleton"
ANDROID_LIB="$WBC/build-android/libwbcrypto.a"
if [ -f "$ANDROID_LIB" ] && [ "$FORCE" -eq 0 ]; then
    info "reusing $ANDROID_LIB (use --force to rebuild)"
else
    OMVLL_ARG="--no-omvll"
    [ "$OMVLL" -eq 1 ] && OMVLL_ARG=""
    info "cross-building the runtime library (${OMVLL_ARG:---omvll}) …"
    # shellcheck disable=SC2086
    ( cd "$WBC" && NDK="$NDK" ./scripts/build_android.sh --abi "$ABI" --api "$API" $OMVLL_ARG ) \
        || die "scripts/build_android.sh failed"
fi
[ -f "$ANDROID_LIB" ] || die "expected $ANDROID_LIB after build_android.sh"

mkdir -p "$SOPACK/assets/wbc"
cp "$ANDROID_LIB" "$WBC/include/wbcrypto.h" "$SOPACK/assets/wbc/"
ok "assets/wbc/ refreshed from $WBC/build-android"

SKEL="$SOPACK/sopack/stubs/sopk_rt_$ABI.so"
mkdir -p "$(dirname "$SKEL")"
TRACE_FLAGS=""
[ "$RELEASE" -eq 0 ] && TRACE_FLAGS="-DSOPK_RT_LOG -llog"

# clang++ (not clang: the archive is C++), libc++ STATIC (a libc++_shared.so dependency would be
# another .so to ship and the packer rejects it), -x c because sopk_rt.c is C, and
# --no-undefined so a 1.x archive fails HERE instead of on device. See the doc for each.
#
# -g0 and -ffile-prefix-map are load-bearing for static-analysis resistance, not tidiness: a
# default build carries ~2.7 MB of DWARF naming every function (sopk_rt_ctor, the wbc_* API, the
# VM handlers) plus the absolute host source paths, which leak a developer username and pin the
# vendored libsodium version. The packer strips what it can at pack time, but doing it here is
# what keeps the artifact honest. Note -ffile-prefix-map only rewrites paths for THIS file;
# strings baked into libwbcrypto.a need the same flag in the whitebox-cryptography build.
link_skeleton() {   # link_skeleton <extra flags…>
    # shellcheck disable=SC2086
    "$CXX" --target="${ABI_TRIPLE}${API}" -fPIC -shared -O2 -g0 \
        -ffile-prefix-map="$WBC=." -ffile-prefix-map="$SOPACK=." \
        -fvisibility=hidden -Wl,--exclude-libs,ALL -Wl,--no-undefined \
        "$@" \
        -I"$WBC/include" -I"$SOPACK/stub" \
        -x c "$SOPACK/stub/sopk_rt.c" -x none \
        "$SOPACK/assets/wbc/libwbcrypto.a" \
        $TRACE_FLAGS \
        -o "$SKEL" 2>"$TMP/link.log"
}

info "linking the helper skeleton …"
if ! link_skeleton -static-libstdc++; then
    if grep -qi "static-libstdc++\|unsupported option" "$TMP/link.log"; then
        warn "-static-libstdc++ not accepted; retrying with the explicit libc++ archives"
        SYSROOT="$NDK/toolchains/llvm/prebuilt/$HOSTTAG/sysroot"
        LIBDIR="$SYSROOT/usr/lib/${ABI_TRIPLE%%-*}-linux-android"
        [ -d "$LIBDIR" ] || LIBDIR="$SYSROOT/usr/lib/$ABI_TRIPLE"
        link_skeleton "$LIBDIR/libc++_static.a" "$LIBDIR/libc++abi.a" \
            || { cat "$TMP/link.log" >&2; die "skeleton link failed"; }
    else
        cat "$TMP/link.log" >&2
        if grep -q "undefined reference to \`wbc_" "$TMP/link.log"; then
            die "the archive in assets/wbc/ is missing key-wrap symbols, i.e. it is 1.x.
       --no-undefined caught it here instead of on device. Re-run with --force."
        fi
        die "skeleton link failed (log above)"
    fi
fi
ok "skeleton built: $SKEL"

# -g0 stops OUR debug info; the static archive still contributes its own symbols, so strip.
# --strip-all removes .symtab/.strtab/.comment and any remaining .debug_*, and keeps .dynsym /
# .dynstr / the section header table — which is what bionic needs. This is NOT the section-header
# stripping that docs/static-analysis-hardening.md §Method 3 rejected (that zeroed e_shoff).
STRIP="$(dirname "$CXX")/llvm-strip"
if [ -x "$STRIP" ]; then
    before=$(wc -c <"$SKEL")
    "$STRIP" --strip-all "$SKEL" || die "llvm-strip failed on $SKEL"
    ok "stripped: $before -> $(wc -c <"$SKEL") bytes"
else
    warn "llvm-strip not found at $STRIP; the packer will strip at pack time instead"
fi

# ---- Phase 4 PASS checks ---------------------------------------------------------------
info "checking the skeleton …"

NEEDED="$("$READELF" -dW "$SKEL" | awk '/NEEDED/ {gsub(/[][]/,"",$5); print $5}')"
BAD_NEEDED=""
for n in $NEEDED; do
    case "$n" in
        libc.so|libm.so|libdl.so|liblog.so) ;;
        *) BAD_NEEDED="$BAD_NEEDED $n" ;;
    esac
done
if [ -n "$BAD_NEEDED" ]; then
    case "$BAD_NEEDED" in
        *libc++_shared.so*) die "helper depends on libc++_shared.so — the static libc++ did not
       take effect. It must be statically linked, or the packer will reject the skeleton." ;;
    esac
    die "helper has non-bionic DT_NEEDED:$BAD_NEEDED — something was not statically linked"
fi
ok "DT_NEEDED is bionic-only:$(printf ' %s' $NEEDED)"

EXPORTS="$("$READELF" --dyn-syms "$SKEL" \
    | awk '($5=="GLOBAL"||$5=="WEAK") && $7!="UND" && $8!="" {print $8}' | sort -u)"
if [ -n "$EXPORTS" ]; then
    printf '%s\n' "$EXPORTS" | sed 's/^/      /' >&2
    die "helper EXPORTS the symbols above; --exclude-libs did not take effect. Add a version
       script instead:  printf '{ local: *; };\\n' > /tmp/hide-all.map
       then add -Wl,--version-script=/tmp/hide-all.map to the link line."
fi
ok "exports nothing"

IMPORTS="$("$READELF" --dyn-syms "$SKEL" \
    | awk '$7=="UND" && $8 ~ /^(wbc_|sodium_)/ {print $8}' | sort -u)"
if [ -n "$IMPORTS" ]; then
    printf '%s\n' "$IMPORTS" | sed 's/^/      /' >&2
    die "helper IMPORTS the symbols above instead of defining them — it linked against a 1.x
       libwbcrypto.a. bionic could not load it, and dlopen of the TARGET would fail with it."
fi
ok "imports no wbc_*/sodium_* (so it will load)"

( cd "$SOPACK" && python3 - "$SKEL" <<'PY'
import sys
from sopack.rt_meta import HELPER_BUILD_MARKER, REGION_VERSION
data = open(sys.argv[1], 'rb').read()
if HELPER_BUILD_MARKER not in data:
    sys.exit(f"ERROR: skeleton lacks the v{REGION_VERSION} build marker "
             f"({HELPER_BUILD_MARKER.hex()}) — it was built from an older stub/sopk_rt.c. "
             "sopack would refuse it at pack time.")
PY
) || exit 1
ok "carries the build marker the packer greps for"

# ---- next step -------------------------------------------------------------------------
cat <<EOF

==> Host phases 1-4 PASS. Phase 5 is yours to run — it needs your APK and lib names:

  cd "$SOPACK"
  mkdir -p output
  python3 -m sopack.cli pack <your.apk> \\
    --lib "libfoo.so,libbar.so" \\
    --cipher wbaes \\
    --abi $ABI \\
    --wb-keygen "$SOPACK_WBKEYGEN" \\
    -o output/packed.apk \\
    --verify

  Quote the --lib list: it is ONE argv word, so an unquoted space after a comma makes
  argparse reject the second name.

Then verify the packed APK and go to device, per docs/wbaes-verification.md Phases 5-6.
EOF
if [ "$RELEASE" -eq 0 ]; then
    cat <<EOF

  This skeleton is a TRACING build, so the helper logs a per-phase timing line at load:
      adb logcat | grep -E 'sopk_rt|linker|dlopen|DEBUG'
  It also needs 'pack --allow-helper-log', because those same lines hand an attacker the
  .text address and length to dump. Re-run WITHOUT --trace before shipping.
EOF
else
    cat <<EOF

  This skeleton is a RELEASE build: no logcat output, so a failure at load is a SIGABRT
  with no message (by design — see the fail-closed note in stub/sopk_rt.c). If the app
  crashes on device, rebuild with --trace and pack with --allow-helper-log to find out why.
EOF
fi
