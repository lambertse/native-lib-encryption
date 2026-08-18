#!/usr/bin/env bash
#
# device_test.sh - pack every APK in test_apks/ with cipher wbaes, run each one on a connected
# device, and report whether the injected helper actually decrypted what the packer claims it
# encrypted. Never aborts mid-run: one bad APK is a row in the report, not the end of the run.
#
# The failure this exists to catch is SILENT. A library that was packed but whose helper ctor
# never ran produces no crash and no message, so a human watching logcat records a pass. So the
# pass criterion is not "no crash" - it is "no crash AND the number of distinct libraries that
# logged a decrypt equals the number `sopack pack` said it injected".
#
# Usage:
#   ./scripts/device_test.sh                        # build once, then every test_apks/*.apk
#   ./scripts/device_test.sh --only Flappy          # just the APKs whose name matches
#   ./scripts/device_test.sh --skip-build --watch 30
#   ./scripts/device_test.sh --dry-run              # preflight + print, touch no device
#
# Options:
#   --only PAT        only APKs whose filename contains PAT (case-insensitive). Repeatable.
#   --watch N         seconds to watch each app after launch (default 15). A late-dlopen'ed
#                     library (the Flutter libapp.so case) legitimately needs a longer window;
#                     it shows up as WARN, not FAIL.
#   --skip-build      do not run build_wbaes.sh; assert the skeletons exist and are a --trace
#                     build. Use when you already built and are re-running the matrix.
#   --force-build     pass --force to build_wbaes.sh (redoes the cached host wb_keygen and
#                     Android libwbcrypto.a phases, and re-runs the unit tests). Slow.
#   --keep-installed  leave each app installed after its test (default: uninstall, to keep
#                     from filling device storage - packed APKs are LARGER than the input).
#   --dry-run         run preflight and aapt, print the pack/adb commands, touch no device.
#   --apks DIR        default <repo>/test_apks (the local APK corpus)
#   --out DIR         default <repo>/output/testrun
#   --abi ABI         default arm64-v8a (the only ABI sopack protects in practice)
#   --wbc PATH        whitebox-cryptography checkout.  Else $WBC, else the pinned submodule
#   --ndk PATH        Android NDK root.                Else $NDK/$ANDROID_NDK_HOME/$ANDROID_NDK_ROOT
#   --wb-keygen PATH  host wb_keygen.                  Else $SOPACK_WBKEYGEN, else <repo>/vendor/wbc/bin/wb_keygen
#
# The APKs this produces are packed against a --trace (-DSOPK_RT_LOG) skeleton and need
# a config saying `logging.allow-helper-log: true`, which this script writes for itself.
# They log the target name, .text address and size at load.
# They are diagnostic builds. DO NOT SHIP THEM.
#
# Bash 3.2 compatible on purpose (macOS /bin/bash), same as scripts/_common.sh: no associative
# arrays, no mapfile, and no timeout(1) - which stock macOS does not have either.
set -euo pipefail

# Every match in this script is against an ASCII protocol string (sopack's own output, logcat
# tags, adb's replies), but the HAYSTACKS are arbitrary bytes: a logcat buffer carries whatever
# the apps under test logged, and the skeleton check greps an ELF. In a UTF-8 locale, grep gives
# up on invalid multibyte sequences and reports NO MATCH on data that plainly contains the
# string - which here would silently score a healthy app 0 decrypted. Byte semantics everywhere,
# set once. (Measured: a UTF-8 `grep liblog` on the real sopk_rt skeleton returns 1.)
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOPACK="$(cd "$HERE/.." && pwd)"
# shellcheck source=scripts/_common.sh
. "$HERE/_common.sh"

ABI="arm64-v8a"
WATCH=15
SKIP_BUILD=0
FORCE_BUILD=0
KEEP_INSTALLED=0
DRY_RUN=0
APK_DIR="$SOPACK/test_apks"
OUTDIR="$SOPACK/output/testrun"
WBC_ARG=""
NDK_ARG=""
WBKEYGEN_ARG=""
ONLY_PATS=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --only)           ONLY_PATS="$ONLY_PATS
$2"; shift 2 ;;
        --watch)          WATCH="$2"; shift 2 ;;
        --skip-build)     SKIP_BUILD=1; shift ;;
        --force-build)    FORCE_BUILD=1; shift ;;
        --keep-installed) KEEP_INSTALLED=1; shift ;;
        --dry-run)        DRY_RUN=1; shift ;;
        --apks)           APK_DIR="$2"; shift 2 ;;
        --out)            OUTDIR="$2"; shift 2 ;;
        --abi)            ABI="$2"; shift 2 ;;
        --wbc)            WBC_ARG="$2"; shift 2 ;;
        --ndk)            NDK_ARG="$2"; shift 2 ;;
        --wb-keygen)      WBKEYGEN_ARG="$2"; shift 2 ;;
        # 2..43 is the header comment block: it ENDS at the bash-3.2 note, the line before
        # `set -euo pipefail`. Adjust if the header grows, or --help starts printing shell code.
        -h|--help)        sed -n '2,43p' "$0"; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

case "$WATCH" in
    ''|*[!0-9]*) die "--watch takes a whole number of seconds, got: $WATCH" ;;
esac

# ============================================================================================
# preflight - everything here aborts the whole run, because a run that starts with any of it
# wrong produces a report full of identical failures that look like packer bugs.
# ============================================================================================
say "preflight"

need python3
need adb "device automation needs the Android platform-tools on PATH"
( cd "$SOPACK" && python3 -c 'import sopack' >/dev/null 2>&1 ) \
    || die "cannot import sopack from $SOPACK - run: pip install -e ."
SOPACK_VER="$( cd "$SOPACK" && python3 -c 'import sopack; print(sopack.__version__)' 2>/dev/null || echo "?" )"

[ -d "$APK_DIR" ] || die "--apks $APK_DIR is not a directory"

# ---- toolchain paths -----------------------------------------------------------------------
# The keygen is resolved here as a PRECONDITION, not to pass down: sopack has no --wb-keygen
# flag any more, and provision.find_wb_keygen probes vendor/wbc/bin/ itself. Checking it up
# front still beats letting every pack in the loop fail identically at the same preflight.
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
NDK="${NDK_ARG:-${NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-$SDK/ndk/29.0.14206865}}}}"
[ -n "$WBC_ARG" ] && WBC="$WBC_ARG"
resolve_wbc "$SOPACK" --no-prompt
WBC="$(cd "$WBC" && pwd)"
WBKEYGEN="${WBKEYGEN_ARG:-${SOPACK_WBKEYGEN:-$SOPACK/vendor/wbc/bin/wb_keygen}}"

if [ ! -x "$WBKEYGEN" ]; then
    die "no host wb_keygen at $WBKEYGEN.
       Run ./scripts/build_wbaes.sh - it builds one from the pinned submodule and installs it
       at vendor/wbc/bin/wb_keygen, where sopack finds it unaided. NOTE: a wb_keygen delivered
       out of band is an ANDROID build and does not run on this host."
fi
# A --wb-keygen passed to THIS script can no longer be forwarded on the sopack command line, so
# hand it over the one channel that still exists. Unset, sopack's own probe wins - which is the
# normal path and points at the same file.
[ -n "$WBKEYGEN_ARG" ] && export SOPACK_WBKEYGEN="$WBKEYGEN"
if [ "$SKIP_BUILD" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    if [ ! -d "$NDK" ]; then
        warn "NDK=$NDK does not exist. Installed NDKs under $SDK/ndk:"
        ls -1 "$SDK/ndk" 2>/dev/null | sed 's/^/      /' || warn "      (none)"
        die "pass --ndk, export NDK, or re-run with --skip-build"
    fi
fi
info "sopack $SOPACK_VER at $SOPACK"
info "WBC       $WBC"
info "NDK       $NDK"
info "wb_keygen $WBKEYGEN"

# ---- aapt ----------------------------------------------------------------------------------
# Rarely on PATH on macOS; it lives in the SDK's build-tools. `aapt2 dump badging` takes the
# same subcommand and prints the same package:/launchable-activity: lines, so either will do.
AAPT=""
if have aapt; then
    AAPT="$(command -v aapt)"
elif have aapt2; then
    AAPT="$(command -v aapt2)"
elif [ -d "$SDK/build-tools" ]; then
    # Numeric sort on the version triple: `sort -r` alone would rank 9.0.0 above 35.0.0, and an
    # old aapt fails to parse a modern APK.
    for v in $(ls -1 "$SDK/build-tools" 2>/dev/null | sort -t. -k1,1nr -k2,2nr -k3,3nr); do
        if [ -x "$SDK/build-tools/$v/aapt" ]; then AAPT="$SDK/build-tools/$v/aapt"; break; fi
        if [ -x "$SDK/build-tools/$v/aapt2" ]; then AAPT="$SDK/build-tools/$v/aapt2"; break; fi
    done
fi
[ -n "$AAPT" ] || die "no aapt/aapt2 found on PATH or under $SDK/build-tools -
       install the Android SDK build-tools, or put aapt on PATH"
info "aapt      $AAPT"

# ---- device --------------------------------------------------------------------------------
ADB=(adb)
if [ -n "${ANDROID_SERIAL:-}" ]; then
    ADB=(adb -s "$ANDROID_SERIAL")
fi
adb_() { "${ADB[@]}" "$@"; }

DEV_MODEL="?" ; DEV_REL="?" ; DEV_ABIS="?" ; DEV_PAGESZ="?"
if [ "$DRY_RUN" -eq 1 ]; then
    warn "--dry-run: skipping every device check and every device command"
else
    DEVCOUNT="$(adb devices | awk 'NR>1 && $2=="device"' | wc -l | tr -d ' ')"
    if [ "$DEVCOUNT" -eq 0 ]; then
        adb devices | sed 's/^/      /' >&2
        die "no device in state 'device'. Plug one in, unlock it, accept the USB-debugging prompt."
    fi
    if [ "$DEVCOUNT" -gt 1 ] && [ -z "${ANDROID_SERIAL:-}" ]; then
        adb devices | sed 's/^/      /' >&2
        die "$DEVCOUNT devices connected - every adb call would fail with 'more than one device'.
       Export ANDROID_SERIAL=<serial> to pick one."
    fi
    adb_ wait-for-device
    DEV_MODEL="$(adb_ shell getprop ro.product.model 2>/dev/null | tr -d '\r')"
    DEV_REL="$(adb_ shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')"
    DEV_ABIS="$(adb_ shell getprop ro.product.cpu.abilist 2>/dev/null | tr -d '\r')"
    DEV_PAGESZ="$(adb_ shell getconf PAGE_SIZE 2>/dev/null | tr -d '\r')"
    info "device    $DEV_MODEL (Android $DEV_REL), abis=$DEV_ABIS, PAGE_SIZE=$DEV_PAGESZ"

    # The worst false pass in this whole harness: on a device without the packed ABI, every app
    # produces zero sopk_rt lines AND zero crashes, and "no crash" reads as clean.
    case ",$DEV_ABIS," in
        *",$ABI,"*) ;;
        *) die "device abilist ($DEV_ABIS) does not include $ABI, so nothing this script packs
       would ever load there: every app would report 0 decrypts and 0 crashes, which is
       indistinguishable from a clean pass. Refusing to run." ;;
    esac
fi

# ============================================================================================
# phase 0 - build the skeletons ONCE. They are per-ABI, not per-APK.
# ============================================================================================
RT_SKEL="$SOPACK/sopack/stubs/sopk_rt_$ABI.so"
WB_SKEL="$SOPACK/sopack/stubs/sopk_wb_$ABI.so"

if [ "$SKIP_BUILD" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then
    say "skipping build_wbaes.sh"
    if [ "$DRY_RUN" -eq 0 ]; then
        [ -f "$RT_SKEL" ] || die "--skip-build but $RT_SKEL is missing - run without --skip-build"
        [ -f "$WB_SKEL" ] || die "--skip-build but $WB_SKEL is missing - run without --skip-build"
        # A release skeleton logs nothing, so every app would score 0 decrypts and get reported
        # WARN/FAIL for a reason that has nothing to do with the pack. Catch it here.
        #
        # `LC_ALL=C grep -a` is load-bearing, not decoration: a plain grep over these ELF files
        # returns 1 even when the string IS present (it gives up on the invalid multibyte
        # sequences around it), so the naive check rejects every CORRECT tracing skeleton.
        # __android_log_print rather than "liblog" because that import is exactly what
        # `sopack pack` refuses unless the config says logging.allow-helper-log: true.
        # BOTH skeletons, not just the helper. They are built separately, so a release provider
        # beside a trace helper is a real state - and it is the sneaky one: the per-library
        # `- OK` lines still appear (they come from sopk_rt), so the run looks healthy, while
        # every sopk_wb line the classifier reads for the kdf tier and the ABI-mismatch check
        # is silently absent. Absence would then read as "nothing wrong".
        for skel in "$RT_SKEL" "$WB_SKEL"; do
            if ! LC_ALL=C grep -qa '__android_log_print' "$skel"; then
                die "$skel does not import __android_log_print, so it is a RELEASE (non-trace)
       build: it emits no logcat lines at all, and this harness would read that silence as
       a clean result - a failure that has nothing to do with your APKs.
       Rebuild BOTH skeletons with: ./scripts/build_wbaes.sh --trace"
            fi
        done
        ok "skeletons present, and both are tracing builds"
    fi
else
    say "building the wbaes skeletons (--trace) - once for the whole run"
    BUILD_ARGS=(--trace --abi "$ABI" --wbc "$WBC" --ndk "$NDK")
    [ "$FORCE_BUILD" -eq 1 ] && BUILD_ARGS+=(--force)
    BUILD_LOG="$OUTDIR/build_wbaes.log"
    mkdir -p "$OUTDIR"
    if ! ( cd "$SOPACK" && ./scripts/build_wbaes.sh "${BUILD_ARGS[@]}" ) 2>&1 | tee "$BUILD_LOG"; then
        die "build_wbaes.sh failed - see $BUILD_LOG. Nothing was packed."
    fi
    grep -q 'Host phases 1-4 PASS' "$BUILD_LOG" \
        || die "build_wbaes.sh did not print its 'Host phases 1-4 PASS' sentinel - see $BUILD_LOG"
    ok "skeletons built: $(basename "$RT_SKEL") + $(basename "$WB_SKEL")"
fi

# ============================================================================================
# the matrix
# ============================================================================================
mkdir -p "$OUTDIR"
TSV="$OUTDIR/summary.tsv"
: >"$TSV"

# ---- the harness's own pack config -------------------------------------------------------
# Everything except the input and output APK is configured in YAML now, so the harness writes
# the settings it needs and passes --config explicitly. Two things make the explicit path
# non-optional rather than tidiness:
#
#   1. sopack falls back to ./config.yaml when no --config is given, and the pack below runs
#      inside `( cd "$SOPACK" && ... )`. A developer's own config.yaml at the repo root would
#      silently override this harness and the run would report on settings nobody chose.
#   2. $OUTDIR may be relative, and the pack runs after that `cd`, so the path has to be
#      absolute or it resolves against the wrong directory.
#
# Written here, before the per-APK loop AND before the --dry-run branch, so the command the
# dry run prints refers to a file that actually exists.
PACK_CONFIG="$(cd "$OUTDIR" && pwd)/sopack-config.yaml"
cat >"$PACK_CONFIG" <<EOF
# Generated by scripts/device_test.sh - regenerated on every run, do not edit.
#
# cipher stays EXPLICIT even though wbaes is the default: this harness exists to exercise the
# white-box path, and it must keep doing that if the default ever moves.
cipher: wbaes
abis:
  - $ABI
logging:
  # The whole point of this harness: the tracing helper logs one line per decrypted library,
  # which is what the pass criterion counts. Packing one is refused without this, and the
  # resulting APK is NOT shippable.
  allow-helper-log: true
EOF
info "pack config: $PACK_CONFIG"

# wanted APK - true unless --only was given and no pattern matches (case-insensitive substring
# on the basename). The `while ... <<EOF` form keeps the loop in THIS shell, so `return` works;
# a `printf | while` pipeline would run it in a subshell and the return would be lost.
wanted() {
    [ -z "$ONLY_PATS" ] && return 0
    local lower pat plower
    lower="$(basename "$1" | tr 'A-Z' 'a-z')"
    while IFS= read -r pat; do
        [ -z "$pat" ] && continue
        plower="$(printf '%s' "$pat" | tr 'A-Z' 'a-z')"
        case "$lower" in *"$plower"*) return 0 ;; esac
    done <<EOF
$ONLY_PATS
EOF
    return 1
}

APKS=""
for apk in "$APK_DIR"/*.apk; do
    [ -f "$apk" ] || continue          # no match -> the glob itself
    if wanted "$apk"; then
        APKS="$APKS$apk
"
    fi
done
[ -n "$APKS" ] || die "no APKs to test under $APK_DIR${ONLY_PATS:+ matching --only}"
TOTAL="$(printf '%s' "$APKS" | grep -c . || true)"

say "$TOTAL APK(s) to test - watch window ${WATCH}s each, output under $OUTDIR"

IDX=0

# Into a plain indexed array - bash 3.2 has those, just not associative ones. The main loop must
# NOT be a `... | while read` pipeline: that runs in a subshell, and every report row would be
# discarded when it exits.
APK_LIST=()
while IFS= read -r line; do
    [ -n "$line" ] && APK_LIST+=("$line")
done <<EOF
$APKS
EOF

for APK in "${APK_LIST[@]}"; do
    IDX=$((IDX + 1))
    BASE="$(basename "$APK")"
    SLUG="$(printf '%s' "$BASE" | sed 's/\.apk$//' | tr -cd 'A-Za-z0-9._-')"
    DIR="$OUTDIR/$SLUG"
    OUT_APK="$DIR/packed.apk"
    mkdir -p "$DIR"

    step "$IDX" "$TOTAL" "$BASE"

    STATUS=""
    NOTE=""
    PKG=""
    ACT=""
    INJECTED=0
    DECRYPTED=0

    # ---- 1. identify ------------------------------------------------------------------------
    if ! "$AAPT" dump badging "$APK" >"$DIR/badging.txt" 2>"$DIR/badging.err"; then
        warn "aapt dump badging failed: $(head -1 "$DIR/badging.err")"
        STATUS="PACK-FAIL"; NOTE="aapt could not parse the APK"
    else
        PKG="$(awk -F"'" '/^package: name=/{print $2; exit}' "$DIR/badging.txt")"
        ACT="$(awk -F"'" '/^launchable-activity: name=/{print $2; exit}' "$DIR/badging.txt")"
        if [ -z "$PKG" ]; then
            STATUS="PACK-FAIL"; NOTE="no package name in badging output"
        else
            info "package  $PKG${ACT:+  activity $ACT}"
        fi
    fi

    # ---- 2. pack ---------------------------------------------------------------------------
    if [ -z "$STATUS" ]; then
        # Everything but the APKs comes from $PACK_CONFIG, written once above. It is passed
        # explicitly and absolutely because this runs inside `cd "$SOPACK"` and sopack would
        # otherwise pick up a developer's own ./config.yaml at the repo root without saying so.
        PACK_CMD=(python3 -m sopack.cli pack "$APK"
                  -o "$OUT_APK"
                  --config "$PACK_CONFIG")
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '    would run: '; printf '%q ' "${PACK_CMD[@]}"; printf '\n'
            printf '    with config %s:\n' "$PACK_CONFIG"
            sed 's/^/      | /' "$PACK_CONFIG"
            printf '    would run: adb uninstall %q\n' "$PKG"
            printf '    would run: adb install -r %q\n' "$OUT_APK"
            printf '    would run: adb logcat -c -b all\n'
            printf '    would run: adb shell monkey -p %q -c android.intent.category.LAUNCHER 1\n' "$PKG"
            printf '    would run: sleep %s; adb logcat -d -b all -v threadtime\n' "$WATCH"
            STATUS="DRY-RUN"; NOTE="nothing was packed or installed"
        else
            info "packing (auto-select: every lib/$ABI/*.so)"
            if ! ( cd "$SOPACK" && "${PACK_CMD[@]}" ) >"$DIR/pack.log" 2>&1; then
                STATUS="PACK-FAIL"
                NOTE="$(grep -m1 '^error: ' "$DIR/pack.log" || tail -3 "$DIR/pack.log" | tr '\n' ' ')"
                warn "pack failed: $NOTE"
            else
                INJECTED="$(awk '/^Injected [0-9]+ librar/{print $2; exit}' "$DIR/pack.log")"
                [ -n "$INJECTED" ] || INJECTED=0
                # Auto-select is fail-soft by design (CLAUDE.md §Library selection): an
                # un-injectable prebuilt is a recorded skip, not a dead pack. Report it, do not
                # fail on it.
                if grep -q 'ship in CLEARTEXT' "$DIR/pack.log"; then
                    CLEAR="$(awk '/ship in CLEARTEXT/{f=1;next} f&&/^  /{n++} f&&/^$/{exit} END{print n+0}' "$DIR/pack.log")"
                    NOTE="$CLEAR cleartext skip(s)"
                    warn "$CLEAR selected librar(y/ies) could not be injected and ship in CLEARTEXT"
                fi
                if [ "$INJECTED" -eq 0 ]; then
                    # Exit 0 with nothing injected is not a bug - the APK may simply have no
                    # lib/$ABI/*.so. Do not send it to the device; there is nothing to observe.
                    STATUS="NO-TARGETS"
                    NOTE="no lib/$ABI/*.so to protect${NOTE:+; $NOTE}"
                    warn "$STATUS - skipping the device phase"
                else
                    ok "injected $INJECTED librar$([ "$INJECTED" -eq 1 ] && echo y || echo ies)"
                fi
            fi
        fi
    fi

    # ---- 3-4. uninstall, install ------------------------------------------------------------
    if [ -z "$STATUS" ]; then
        # sopack re-signs with a fresh certificate, so this is a new app identity and
        # `install -r` over the original always fails. Uninstall first, unconditionally.
        adb_ uninstall "$PKG" >"$DIR/uninstall.log" 2>&1 || true
        info "installing ($(du -h "$OUT_APK" 2>/dev/null | awk '{print $1}'))"
        # `adb install` can report failure on stdout with a zero status, so read the output.
        adb_ install -r "$OUT_APK" >"$DIR/install.log" 2>&1 || true
        if ! grep -q '^Success' "$DIR/install.log"; then
            STATUS="INSTALL-FAIL"
            # Append: NOTE may already carry the cleartext-skip count from the pack step, and
            # that is exactly the sort of detail that must not be lost to a later failure.
            WHY="$(grep -o 'INSTALL_[A-Z_]*' "$DIR/install.log" | head -1)"
            [ -n "$WHY" ] || WHY="$(tail -2 "$DIR/install.log" | tr '\n' ' ')"
            NOTE="${NOTE:+$NOTE; }$WHY"
            warn "install failed: $WHY"
        else
            ok "installed"
        fi
    fi

    # ---- 5. launch --------------------------------------------------------------------------
    if [ -z "$STATUS" ]; then
        adb_ logcat -c -b all >/dev/null 2>&1 || adb_ logcat -c >/dev/null 2>&1 || true
        adb_ shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 \
            >"$DIR/monkey.log" 2>&1 || true
        # monkey exits 0 even when it cannot launch anything, and `adb shell` does not
        # propagate exit codes reliably anyway - so read its stdout, not its status.
        if grep -q 'No activities found\|monkey aborted\|\*\* Error' "$DIR/monkey.log"; then
            WHY=""
            if [ -n "$ACT" ]; then
                warn "monkey could not launch; falling back to am start -n $PKG/$ACT"
                adb_ shell am start -n "$PKG/$ACT" >>"$DIR/monkey.log" 2>&1 || true
                if grep -q 'Error type\|does not exist\|Exception' "$DIR/monkey.log"; then
                    WHY="neither monkey nor am start could launch it"
                fi
            else
                WHY="no launcher activity in the manifest"
            fi
            if [ -n "$WHY" ]; then
                STATUS="LAUNCH-FAIL"
                NOTE="${NOTE:+$NOTE; }$WHY"
                warn "$STATUS - $WHY"
            fi
        fi
    fi

    # ---- 6. watch ---------------------------------------------------------------------------
    if [ -z "$STATUS" ]; then
        info "watching for ${WATCH}s"
        APP_PID=""
        i=0
        while [ "$i" -lt "$WATCH" ]; do
            sleep 1
            i=$((i + 1))
            if [ -z "$APP_PID" ]; then
                APP_PID="$(adb_ shell pidof "$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')"
            fi
        done
        ALIVE_PID="$(adb_ shell pidof "$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')"

        adb_ logcat -d -b all -v threadtime >"$DIR/logcat-full.txt" 2>/dev/null \
            || adb_ logcat -d -v threadtime >"$DIR/logcat-full.txt" 2>/dev/null || true
        # -a: an app that logs a NUL byte would otherwise make grep call the whole buffer
        # "binary" and print a one-line summary instead of the matches.
        grep -aE 'sopk_rt|sopk_wb|DEBUG|libc |AndroidRuntime|avc: *denied|Fatal signal' \
            "$DIR/logcat-full.txt" >"$DIR/logcat-sopk.txt" 2>/dev/null || true

        # If the app died before we ever caught a pid, recover it from the AMS start line so
        # crash attribution below still works.
        if [ -z "$APP_PID" ]; then
            APP_PID="$(sed -n "s/.*Start proc \([0-9][0-9]*\):$PKG[\/ :].*/\1/p" \
                       "$DIR/logcat-full.txt" | head -1)"
        fi

        # ---- 7. classify --------------------------------------------------------------------
        # Distinct targets, NOT line count: `logcat -d` returns the whole buffer, so a relaunch
        # (monkey's, or a crash-restart) duplicates every OK line and a raw count would exceed
        # what the packer injected.
        DECRYPTED="$(grep -ao "decrypted '[^']*'" "$DIR/logcat-sopk.txt" 2>/dev/null \
                     | sort -u | grep -c . || true)"
        [ -n "$DECRYPTED" ] || DECRYPTED=0

        # Crash lines belong to THIS app only. Two attribution routes, and both are needed:
        # libc's `Fatal signal` line names the thread with a 15-char TRUNCATION of the package
        # ("ey.app"), so only the pid matches it; the debuggerd tombstone header names the
        # package in full but is logged under debuggerd's OWN pid, so only the name matches it.
        # A crash from an unrelated app satisfies neither and is correctly ignored.
        #
        # MOST `avc: denied` LINES ARE NOT CRASHES, and treating them as such reported a healthy
        # app as FAIL. Modern Android denies a pile of harmless probes to every untrusted_app -
        # `proc_max_map_count` is read by ART/Flutter at startup and denied on essentially every
        # device. The app handles it and runs fine. Only the W^X classes are fatal to *us*
        # (docs/BUILDING.md §5): execmod means the loader refused to execute a file-backed page
        # the process wrote, which is precisely what the mremap-onto-anonymous dance exists to
        # avoid. So: execmod/execmem/execheap => crash; every other denial => a note.
        #
        # Bare signal NAMES are not triggers either: crash-reporting SDKs (Crashlytics, Sentry,
        # breakpad) log "installing SIGSEGV handler" at startup, and a real native crash always
        # produces libc's `Fatal signal N` line anyway.
        : >"$DIR/crash.txt"; : >"$DIR/denials.txt"
        awk -v pid="${APP_PID:-}" -v pkg="$PKG" \
            -v crash="$DIR/crash.txt" -v deny="$DIR/denials.txt" '
            function mine() {
                return (pkg != "" && index($0, pkg)) || (pid != "" && $3 == pid)
            }
            /Fatal signal [0-9]|FATAL EXCEPTION|ANR in |>>> .* <<</ {
                if (mine()) print > crash; next }
            /avc: *denied/ && /execmod|execmem|execheap/ {
                if (mine()) print > crash; next }
            /avc: *denied/ {
                if (mine()) print > deny; next }
        ' "$DIR/logcat-full.txt" 2>/dev/null || true
        CRASH_N="$(grep -c . "$DIR/crash.txt" 2>/dev/null || true)"
        [ -n "$CRASH_N" ] || CRASH_N=0
        DENY_N="$(grep -c . "$DIR/denials.txt" 2>/dev/null || true)"
        [ -n "$DENY_N" ] || DENY_N=0
        if [ "$DENY_N" -gt 0 ]; then
            NOTE="${NOTE:+$NOTE; }$DENY_N benign avc denial(s), not W^X (see denials.txt)"
        fi

        # Provider-side sanity, cheap to read while we are here.
        if grep -qa 'abi mismatch' "$DIR/logcat-sopk.txt" 2>/dev/null; then
            NOTE="${NOTE:+$NOTE; }ABI MISMATCH - helper and provider skeletons are out of sync"
        fi
        if ! grep -qa 'blob kdf tier' "$DIR/logcat-sopk.txt" 2>/dev/null; then
            # The provider is a verified tracing build (preflight), so it should always log this
            # once per library. Silence means the provider never ran - do not let the ABSENCE of
            # a warning read as the absence of a problem.
            NOTE="${NOTE:+$NOTE; }provider logged no kdf tier - libsopk_wb.so may never have run"
        elif ! grep -qa 'blob kdf tier = 0' "$DIR/logcat-sopk.txt" 2>/dev/null; then
            NOTE="${NOTE:+$NOTE; }kdf tier is NOT light(0) - startup will be slow"
        fi
        SLOWEST="$(grep -o 'total=[0-9.]*ms' "$DIR/logcat-sopk.txt" 2>/dev/null \
                   | sed 's/total=//;s/ms//' | sort -nr | head -1 || true)"
        if [ -n "$SLOWEST" ]; then
            NOTE="${NOTE:+$NOTE; }slowest lib ${SLOWEST}ms"
        fi

        if [ "$CRASH_N" -gt 0 ]; then
            STATUS="FAIL"
            NOTE="${NOTE:+$NOTE; }$CRASH_N crash line(s): $(head -1 "$DIR/crash.txt" | cut -c1-120)"
            warn "CRASH - see $DIR/crash.txt"
        elif [ -z "$ALIVE_PID" ]; then
            STATUS="FAIL"
            NOTE="${NOTE:+$NOTE; }process is gone after ${WATCH}s with no crash line"
            warn "process died silently"
        elif [ "$DECRYPTED" -lt "$INJECTED" ]; then
            STATUS="WARN"
            NOTE="${NOTE:+$NOTE; }only $DECRYPTED of $INJECTED decrypted in ${WATCH}s (a late dlopen is legitimate - retry with --watch 60)"
            warn "$DECRYPTED/$INJECTED decrypted - app is alive and did not crash"
        elif [ "$DECRYPTED" -gt "$INJECTED" ]; then
            STATUS="WARN"
            NOTE="${NOTE:+$NOTE; }$DECRYPTED distinct decrypts but only $INJECTED injected - stale install?"
            warn "more decrypts than injections"
        else
            STATUS="PASS"
            ok "$DECRYPTED/$INJECTED decrypted, alive, no crash"
        fi
    fi

    # ---- 8. reclaim space -------------------------------------------------------------------
    # Packed APKs are LARGER than the input (libs go in STORED). Ten of these fills a device,
    # and INSTALL_FAILED_INSUFFICIENT_STORAGE on app 7 looks exactly like a packer bug.
    if [ "$DRY_RUN" -eq 0 ] && [ "$KEEP_INSTALLED" -eq 0 ] && [ -n "$PKG" ] \
       && [ "$STATUS" != "NO-TARGETS" ] && [ "$STATUS" != "PACK-FAIL" ]; then
        adb_ uninstall "$PKG" >>"$DIR/uninstall.log" 2>&1 || true
    fi

    printf '%s\n' "$STATUS" >"$DIR/status"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$BASE" "${PKG:--}" "$INJECTED" "$DECRYPTED" \
        "$STATUS" "${NOTE:--}" >>"$TSV"
done

# ============================================================================================
# report
# ============================================================================================
SUMMARY="$OUTDIR/summary.md"
{
    printf '# sopack device test\n\n'
    printf -- '- date: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf -- '- sopack: %s, cipher wbaes, abi %s\n' "$SOPACK_VER" "$ABI"
    printf -- '- device: %s (Android %s), abis `%s`, PAGE_SIZE %s\n' \
        "$DEV_MODEL" "$DEV_REL" "$DEV_ABIS" "$DEV_PAGESZ"
    printf -- '- watch window: %ss per app\n\n' "$WATCH"
    printf '> These packed APKs are built against a `--trace` (`-DSOPK_RT_LOG`) skeleton and\n'
    printf '> packed with `logging.allow-helper-log: true`. They log each target name, `.text` address and\n'
    printf '> size at load. They are diagnostic builds - **do not ship them.**\n\n'
    printf '| APK | package | injected | decrypted | status | note |\n'
    printf '|---|---|---:|---:|---|---|\n'
    awk -F'\t' '{printf "| %s | `%s` | %s | %s | **%s** | %s |\n", $1,$2,$3,$4,$5,$6}' "$TSV"
    printf '\n'
    printf 'Status vocabulary: `PASS` alive + no crash + every injected library decrypted; '
    printf '`WARN` alive + no crash but the decrypt count does not match; `FAIL` crashed or '
    printf 'died; `LAUNCH-FAIL` could not be started; `PACK-FAIL` / `INSTALL-FAIL` never '
    printf 'reached the device; `NO-TARGETS` nothing to protect for this ABI.\n\n'
    printf 'Liveness is `pidof <package>`, which covers the main process only. A crash in an\n'
    printf '`android:process=":remote"` child is caught by the log filter, not by that check.\n\n'
    printf 'A crash means `Fatal signal`, `FATAL EXCEPTION`, an ANR, a tombstone header, or an\n'
    printf '`execmod`/`execmem`/`execheap` denial. Every OTHER `avc: denied` goes to the app'"'"'s\n'
    printf '`denials.txt` and is only a note: Android denies harmless probes (`max_map_count` is\n'
    printf 'read by ART/Flutter at startup) to every untrusted app, and those are not failures.\n'
} >"$SUMMARY"

printf '\n'
say "results"
{
    printf 'APK\tPACKAGE\tINJ\tDEC\tSTATUS\tNOTE\n'
    cat "$TSV"
} | awk -F'\t' '{printf "  %-40.40s %-40.40s %4s %4s  %-12s %.70s\n", $1,$2,$3,$4,$5,$6}'

N_PASS="$(awk -F'\t' '$5=="PASS"' "$TSV" | grep -c . || true)"
N_WARN="$(awk -F'\t' '$5=="WARN"' "$TSV" | grep -c . || true)"
N_BAD="$(awk -F'\t' '$5=="FAIL"||$5=="PACK-FAIL"||$5=="INSTALL-FAIL"' "$TSV" | grep -c . || true)"

printf '\n'
info "$N_PASS pass, $N_WARN warn, $N_BAD hard failure(s)"
info "report:  $SUMMARY"
info "per-app: $OUTDIR/<name>/{pack.log,logcat-full.txt,logcat-sopk.txt,crash.txt,denials.txt}"

if [ "$N_BAD" -gt 0 ]; then
    printf '\n'
    warn "$N_BAD app(s) failed - the run completed, but exit status is 1"
    exit 1
fi
exit 0
