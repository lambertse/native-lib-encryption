#!/usr/bin/env bash
#
# artifact_generation.sh - build the portable pack bundle in artifacts/: everything a SECOND
# machine needs to run `sopack pack`, and nothing it does not.
#
# The split that makes this possible: of the artifacts sopack needs, only ONE is host-specific.
# The stub blobs and both wbaes skeletons are Android target ELFs - they do not care what packed
# them - so they travel. `wb_keygen` is a native host binary and does not, so the bundle is
# pinned to the OS/arch that generated it and install.sh refuses a mismatched host.
#
# Generation works on macOS and on Linux - the two OSes that can build a native wb_keygen. On
# Linux it is linked STATICALLY (build_wbaes.sh does that), which is what lets a bundle built on
# Debian install on a RHEL-ish target; gate 4 below refuses to ship one that is not. Any other
# OS needs --allow-foreign-host, which omits the keygen and yields a chacha20/xor-only bundle.
#
# Separately, and not the same constraint: cross-building the SKELETONS needs an x86_64 host
# (there is no linux-aarch64 NDK toolchain, and O-MVLL's Linux plugin is x86_64-only). That is
# build_wbaes.sh's problem, and it does not arise under --skip-build.
#
# Scope is PACK-ONLY. The receiving machine runs sopack; it does not rebuild skeletons, so it
# needs no NDK, no cmake/ninja and no whitebox-cryptography checkout. artifacts/README.md spells
# out what it DOES need (JDK, apksigner) - that list is the point of the bundle.
#
# The bundle also carries THE TOOL, as a py3-none-any wheel with this ABI's skeletons baked in as
# package data. That is why the receiving machine needs no sopack checkout at all - it used to be
# told to `git clone` and `pip install -e .`, which is exactly what a machine "without source
# code" cannot do. See "gate 7 + the wheel" below for why the wheel is built from a STAGED tree.
#
# Usage:
#   ./scripts/artifact_generation.sh                       # build, then bundle
#   ./scripts/artifact_generation.sh --skip-build --tar    # bundle what is already built
#   WBC=~/src/whitebox-cryptography ./scripts/artifact_generation.sh --tar
#
# Options:
#   --abi ABI            default arm64-v8a. Selects which skeleton PAIR is built and bundled;
#                        all three stub blobs ship regardless (they are 6-8 KB and committed).
#   --api N              default 24
#   --wbc PATH           whitebox-cryptography checkout. Else $WBC, else the pinned submodule
#                        at third_party/whitebox-cryptography (initialised on demand), else a
#                        sibling <repo>/../whitebox-cryptography.
#   --ndk PATH           Android NDK root.  Else $NDK / $ANDROID_NDK_HOME / $ANDROID_NDK_ROOT
#   --wb-keygen PATH     host wb_keygen. Else $SOPACK_WBKEYGEN, else <repo>/vendor/wbc/bin/
#                        wb_keygen - which is where build_wbaes.sh installs the one it builds,
#                        so --skip-build finds a previous run's keygen without being told.
#   --out DIR            default <repo>/artifacts
#   --skip-build         do not run build_wbaes.sh; bundle what is in sopack/stubs/ already.
#   --rebuild-stubs      also re-run stub/build_stubs.sh. OFF by default because stub_*.bin/.json
#                        are COMMITTED package data and a different LLVM produces different (still
#                        valid) blobs - i.e. a dirty tree you did not ask for.
#   --force              passed to build_wbaes.sh (redoes the cached host wb_keygen and Android
#                        libwbcrypto.a phases). Slow.
#   --allow-foreign-host generate on a host that cannot produce a usable wb_keygen (i.e. neither
#                        macOS nor Linux), or deliberately cut a keygen-free bundle on one that
#                        can. bin/wb_keygen is OMITTED and the bundle's config.yaml pins
#                        cipher: chacha20 (xor also works; wbaes cannot).
#   --allow-unobfuscated-provider
#                        build libsopk_wb.so WITHOUT O-MVLL. The provider is the artifact whose
#                        static-analysis resistance matters most, so this is never implied - not
#                        by the host, not by a missing plugin. It exists as the escape hatch for
#                        a host where the plugin will not load, and it is recorded in
#                        MANIFEST.txt as `provider-obfuscation: none`.
#   --tar                also write ../sopack-bundle-<abi>-<host>-<rev>.tar.gz next to --out.
#
# SOPACK is this script's own repo - never asked for.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOPACK="$(cd "$HERE/.." && pwd)"
# shellcheck source=scripts/_common.sh
. "$HERE/_common.sh"

# Byte semantics: the skeleton gates grep ELF files, and a UTF-8 grep gives up on invalid
# multibyte sequences and reports NO MATCH on data that plainly contains the string. Here that
# would silently pass a TRACING skeleton off as a release build. Same reasoning as
# device_test.sh; set once.
export LC_ALL=C

ABI="arm64-v8a"
API=24
OUT="$SOPACK/artifacts"
WBC_ARG=""
NDK_ARG=""
WBKEYGEN_ARG=""
SKIP_BUILD=0
REBUILD_STUBS=0
FORCE=0
ALLOW_FOREIGN=0
ALLOW_UNOBF=0
MAKE_TAR=0
# 2: the bundle carries sopack-*.whl and MANIFEST.txt gained a `wheel:` field. A format-1 bundle
# installed itself by copying into an existing editable checkout, which no longer exists as a
# flow, so install.sh refuses anything but 2 rather than half-installing.
BUNDLE_FORMAT=2

while [ "$#" -gt 0 ]; do
    case "$1" in
        --abi)                ABI="$2"; shift 2 ;;
        --api)                API="$2"; shift 2 ;;
        --wbc)                WBC_ARG="$2"; shift 2 ;;
        --ndk)                NDK_ARG="$2"; shift 2 ;;
        --wb-keygen)          WBKEYGEN_ARG="$2"; shift 2 ;;
        --out)                OUT="$2"; shift 2 ;;
        --skip-build)         SKIP_BUILD=1; shift ;;
        --rebuild-stubs)      REBUILD_STUBS=1; shift ;;
        --force)              FORCE=1; shift ;;
        --allow-foreign-host) ALLOW_FOREIGN=1; shift ;;
        --allow-unobfuscated-provider) ALLOW_UNOBF=1; shift ;;
        --tar)                MAKE_TAR=1; shift ;;
        # 2..64 is the header comment block; it ends at the "SOPACK is this script's own repo"
        # line, immediately before `set -euo pipefail`. Widen this if the header grows, or
        # --help starts printing shell code.
        -h|--help)            sed -n '2,64p' "$0"; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

TMP="$(mktemp -d "${TMPDIR:-/tmp}/sopack-bundle.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

case "$ABI" in
    arm64-v8a|armeabi-v7a|x86_64) ;;
    *) die "unsupported --abi $ABI (choose arm64-v8a, armeabi-v7a or x86_64)" ;;
esac

STUBDIR="$SOPACK/sopack/stubs"
SKEL="$STUBDIR/sopk_rt_$ABI.so"
PROV="$STUBDIR/sopk_wb_$ABI.so"

# shasum(1) on macOS, sha256sum(1) on Linux. Both emit and accept "<hex>  <path>", so a bundle
# generated on either host verifies on either host.
if have shasum;        then SHA256="shasum -a 256"
elif have sha256sum;   then SHA256="sha256sum"
else die "neither shasum nor sha256sum on PATH - cannot checksum the bundle"
fi

# ---- gate 1: destination guard ---------------------------------------------------------
# FIRST, before the host gate, because this is the data-loss check and it has to be reachable
# on every host. --out defaults into the repo, and the directory this one replaced used to hold
# 640 MB of APK corpus (that is `test_apks/` now). A cleaner that trusts its argument would
# have deleted it.
say "preflight"
if [ -e "$OUT" ]; then
    [ -d "$OUT" ] || die "--out $OUT exists and is not a directory"
    if [ -n "$(find "$OUT" -maxdepth 1 -name '*.apk' -print -quit 2>/dev/null)" ]; then
        die "refusing to clean $OUT - it contains .apk files, so it is an APK corpus (this
       repo keeps one in test_apks/) and not a generated bundle. Point --out elsewhere."
    fi
    if [ -n "$(find "$OUT" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ] \
       && [ ! -f "$OUT/MANIFEST.txt" ]; then
        die "refusing to clean $OUT - it is not empty and has no MANIFEST.txt, so it was not
       produced by this script. Remove it yourself if you meant to, or pass --out DIR."
    fi
    ok "$OUT is safe to regenerate"
fi

# ---- gate 2: host gate -----------------------------------------------------------------
# The bundle is pinned to the host that generated it, because bin/wb_keygen is a native binary
# and sopack/provision.py:_host_incompatible_reason refuses a foreign one BY FILE MAGIC on the
# receiving machine (an ELF on a Mac, a Mach-O on Linux). That check is symmetric, and so is
# install.sh's host-os/host-arch comparison - so the question here is not "is this macOS?" but
# "can this host produce a wb_keygen someone can actually use?".
#
# Two OSes can: macOS, and Linux (where build_wbaes.sh links it statically, so it has no glibc
# floor and installs on any distro). Deliberately not narrowed to Linux/x86_64: the arch that
# matters is the one the RECEIVING machine runs, install.sh checks it, and an aarch64 Linux host
# bundling for an aarch64 Linux pack host is perfectly coherent. What aarch64 Linux cannot do is
# cross-build the skeletons - Google ships no linux-aarch64 NDK toolchain - but that is Phase 4's
# problem and build_wbaes.sh says so precisely, and it does not arise under --skip-build.
HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"
WITH_KEYGEN=1
case "$HOST_OS" in
    Darwin|Linux) ;;
    *)
        if [ "$ALLOW_FOREIGN" -eq 0 ]; then
            die "this host is $HOST_OS/$HOST_ARCH, and a wbaes-capable bundle can only be
       generated on macOS or Linux - the two OSes that can build a usable native wb_keygen.
       Generate there, or pass --allow-foreign-host to build a chacha20/xor-only bundle (no
       wb_keygen)."
        fi
        warn "generating on $HOST_OS/$HOST_ARCH with --allow-foreign-host: bin/wb_keygen is
      OMITTED, so this bundle supports cipher chacha20/xor only, NOT wbaes"
        WITH_KEYGEN=0 ;;
esac
# --allow-foreign-host on a host that COULD carry a keygen is still honoured - it is the
# documented way to cut a deliberately keygen-free bundle - but say so, because otherwise it
# looks like the gate above fired.
if [ "$ALLOW_FOREIGN" -eq 1 ] && [ "$WITH_KEYGEN" -eq 1 ]; then
    warn "--allow-foreign-host on $HOST_OS/$HOST_ARCH, which CAN carry a keygen: omitting
      bin/wb_keygen anyway, so this bundle supports cipher chacha20/xor only"
    WITH_KEYGEN=0
fi
info "host: $HOST_OS/$HOST_ARCH   target: $ABI / android-$API"

need python3
( cd "$SOPACK" && python3 -c 'import sopack' >/dev/null 2>&1 ) \
    || die "cannot import sopack from $SOPACK - run: pip install -e ."
need tar "the bundle is written as a directory tree, and --tar archives it"

NDK="${NDK_ARG:-${NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}}"
# --no-prompt: this script is meant to run unattended in a release step, so resolve_wbc dies
# with the `git submodule update --init` command rather than blocking on a read. It also
# initialises the submodule itself, which is what keeps the old `[ -d "$WBC" ]` trap below from
# firing: an UNINITIALISED submodule is an empty DIRECTORY, so a -d test passes and the failure
# only surfaced 30 lines later as a truncated build log.
[ -n "$WBC_ARG" ] && WBC="$WBC_ARG"
resolve_wbc "$SOPACK" --no-prompt
# vendor/wbc/bin/ is where build_wbaes.sh installs it, and where sopack's own find_wb_keygen
# looks first - so the bundle and the packer agree on one location by construction.
WBKEYGEN="${WBKEYGEN_ARG:-${SOPACK_WBKEYGEN:-$SOPACK/vendor/wbc/bin/wb_keygen}}"

# ---- build (unless --skip-build) -------------------------------------------------------
if [ "$REBUILD_STUBS" -eq 1 ]; then
    # Off by default on purpose: sopack/stubs/stub_*.bin|.json are committed package data, and
    # rebuilding with a different LLVM produces different-but-valid blobs. See
    # build_chacha20.sh's note - expect a dirty tree afterwards and only commit if you meant to.
    say "rebuilding the per-ABI stub blobs (api $API) - this REWRITES tracked files"
    ( cd "$SOPACK" && bash stub/build_stubs.sh "$API" ) || die "stub/build_stubs.sh failed"
fi

if [ "$SKIP_BUILD" -eq 1 ]; then
    warn "--skip-build: bundling whatever is in sopack/stubs/ right now"
    [ -f "$SKEL" ] || die "no $SKEL - drop --skip-build, or build it first"
    [ -f "$PROV" ] || die "no $PROV - drop --skip-build, or build it first"
    # A shared object records no obfuscation state, so this branch genuinely cannot tell an
    # O-MVLL provider from a --no-omvll one. Record that rather than assuming the default held -
    # same reasoning as build_wbaes.sh's warning when it reuses a cached libwbcrypto.a.
    PROVIDER_OBFUSCATION="unknown"
else
    # resolve_wbc already proved this is a usable >= 3.0.0 checkout, header and all - a bare
    # `-d` here would pass on an empty (uninitialised) submodule directory.
    [ -f "$WBC/include/wbcrypto.h" ] || die "no usable whitebox-cryptography at $WBC"
    [ -n "$NDK" ] || die "no Android NDK - pass --ndk PATH or export NDK/ANDROID_NDK_HOME."
    # --omvll is EXPLICIT even though it is build_wbaes.sh's default. A release bundle is the
    # one artifact that must never accidentally ship an unobfuscated provider, and an explicit
    # flag keeps that true if that default ever moves again. The opt-out is equally explicit and
    # only ever comes from the user: nothing here infers it from the host or from a plugin that
    # failed to load, because "it built" would then quietly mean "it built unobfuscated".
    if [ "$ALLOW_UNOBF" -eq 1 ]; then
        warn "--allow-unobfuscated-provider: building libsopk_wb.so WITHOUT O-MVLL. The provider
      carries the sealed blob and every wbc_* call, so this is the artifact whose static
      analysis matters most. MANIFEST.txt will record provider-obfuscation: none."
        say "building the wbaes artifacts via build_wbaes.sh (release, UNOBFUSCATED, $ABI)"
        OMVLL_ARG="--no-omvll"
        PROVIDER_OBFUSCATION="none"
    else
        say "building the wbaes artifacts via build_wbaes.sh (release, obfuscated, $ABI)"
        OMVLL_ARG="--omvll"
        PROVIDER_OBFUSCATION="omvll"
    fi
    BUILD_ARGS="--release $OMVLL_ARG --abi $ABI --api $API"
    [ "$FORCE" -eq 1 ] && BUILD_ARGS="$BUILD_ARGS --force"
    # shellcheck disable=SC2086
    if ! ( cd "$SOPACK" && ./scripts/build_wbaes.sh $BUILD_ARGS --wbc "$WBC" --ndk "$NDK" ) \
            >"$TMP/build.log" 2>&1; then
        tail -30 "$TMP/build.log" >&2
        die "build_wbaes.sh failed (log above). Its gates are the same ones a bundle would
       otherwise hide until the receiving machine packs an APK."
    fi
    # The sentinel build_wbaes.sh prints only after every Phase 1-4 PASS check, same as
    # device_test.sh:241. Exit 0 alone is weaker - a phase can be skipped by a flag.
    grep -q 'Host phases 1-4 PASS' "$TMP/build.log" \
        || die "build_wbaes.sh exited 0 but never printed 'Host phases 1-4 PASS' - it did not
       complete Phase 4, so the skeletons are not trustworthy. Full log: $TMP/build.log"
    ok "build_wbaes.sh reached Host phases 1-4 PASS"
fi

# ---- gates 3-6: they inspect artifacts, so they run AFTER the build --------------------
say "artifact gates"

# 3. Release-skeleton gate. device_test.sh builds --trace skeletons into these exact paths, so
#    "the file exists" says nothing about which build it is. A tracing helper logs the target
#    name, .text address and size at load, and `sopack pack` refuses it unless the config says
#    logging.allow-helper-log - so bundling one ships something either rejected or unsafe.
for so in "$SKEL" "$PROV"; do
    if grep -qa '__android_log_print' "$so"; then
        die "$(basename "$so") is a TRACING build (-DSOPK_RT_LOG): it imports
       __android_log_print. That is almost certainly device_test.sh's skeleton, which writes to
       the same path. Rebuild without --trace (./scripts/build_wbaes.sh --release) and re-run;
       do not ship a diagnostic skeleton."
    fi
done
ok "both skeletons are release builds (no __android_log_print)"

# 4+5. wb_keygen: the one host-specific file, so both its checks are about the RECEIVING machine.
KEYGEN_DESC="omitted (--allow-foreign-host; chacha20/xor only)"
KEYGEN_LINKAGE="n/a"
if [ "$WITH_KEYGEN" -eq 1 ]; then
    [ -x "$WBKEYGEN" ] || die "no runnable host wb_keygen at $WBKEYGEN. Run
       ./scripts/build_wbaes.sh (it installs one there), or pass --wb-keygen PATH."

    # 4. Self-containment: whatever this binary needs at runtime must exist on a machine that has
    #    only the tool. The failure it prevents is identical on both hosts - a link-time
    #    dependency that resolves HERE and is missing THERE, surfacing at first pack, long after
    #    this script said OK - but what counts as safe differs, so the check is per-OS.
    if [ "$HOST_OS" = "Darwin" ]; then
        #  macOS: a Homebrew libsodium/libomp picked up at link time fails with a dyld error on a
        #  Mac that does not have it. Only /usr/lib and /System are guaranteed present. Static
        #  linking is not the answer here - Apple ships no crt0.o for it.
        if have otool; then
            FOREIGN="$(otool -L "$WBKEYGEN" | tail -n +2 | awk '{print $1}' \
                       | grep -v '^/usr/lib/' | grep -v '^/System/' || true)"
            [ -z "$FOREIGN" ] || die "$WBKEYGEN links libraries outside /usr/lib and /System:
$(printf '       %s\n' $FOREIGN)
       Those will not exist on the receiving Mac and dyld fails at first pack. Rebuild it
       statically (the submodule's scripts/gen_blob.sh vendors libsodium; ./scripts/
       build_wbaes.sh --force drives it)."
            ok "wb_keygen links only system libraries"
            KEYGEN_LINKAGE="dynamic (system dylibs only)"
        else
            warn "no otool on PATH - cannot check wb_keygen for non-system dylib dependencies"
            KEYGEN_LINKAGE="dynamic (unverified: no otool)"
        fi
    else
        #  Linux: there is no "guaranteed present" set to allow-list. Distros disagree on glibc
        #  version, and a dynamically linked keygen carries a floor the receiving machine must
        #  meet - `version GLIBC_2.xx not found` at first pack, on the machine least equipped to
        #  debug it. build_wbaes.sh links it statically for exactly this reason, so require the
        #  result: zero DT_NEEDED. That makes this gate STRONGER than the macOS one, not weaker.
        #  ARCHITECTURE FIRST, and it is not redundant with gate 5 running the thing. Docker
        #  Desktop on Apple Silicon runs a linux/amd64 container on an aarch64 kernel, so a
        #  leftover aarch64 keygen in a shared checkout EXECUTES here while `uname -m` reports
        #  x86_64 - gate 5 passes, MANIFEST records host-arch: x86_64, and the bundle is dead on
        #  the real x86_64 target. "It ran" is not evidence of anything on an emulated host.
        KEYGEN_EM="$(elf_machine "$WBKEYGEN")"
        WANT_EM="$(host_elf_machine)"
        [ -n "$KEYGEN_EM" ] || die "$WBKEYGEN is not a little-endian ELF, so it cannot be the
       native host tool this bundle must carry. Rebuild it: ./scripts/build_wbaes.sh --force."
        if [ -n "$WANT_EM" ] && [ "$KEYGEN_EM" != "$WANT_EM" ]; then
            die "$WBKEYGEN is built for $(elf_machine_name "$KEYGEN_EM"), but this host reports
       $HOST_ARCH ($(elf_machine_name "$WANT_EM")). MANIFEST.txt would advertise host-arch:
       $HOST_ARCH and the bundle would carry a binary the receiving machine cannot execute.
       The usual cause is a checkout shared with a container or machine of another architecture -
       build-host/ and vendor/ are gitignored, so they travel with the tree. Fix:
           rm -rf third_party/whitebox-cryptography/build-host vendor/wbc
           ./scripts/build_wbaes.sh --force
       Note this can happen even though the binary RUNS here: an emulated amd64 container on an
       Apple Silicon host executes aarch64 binaries natively."
        fi
        ok "wb_keygen is a native $(elf_machine_name "$KEYGEN_EM") binary"

        NEEDED="$(elf_needed "$WBKEYGEN")" || die "no readelf or objdump on PATH, so the linkage
       of $WBKEYGEN cannot be checked. Do NOT assume static: a dynamically linked keygen
       installs fine here and dies on the target. Install binutils and re-run."
        [ -z "$NEEDED" ] || die "$WBKEYGEN is dynamically linked:
$(printf '       %s\n' $NEEDED)
       On Linux the bundle requires a STATIC keygen - the receiving machine is routinely a
       different distro, and a shared-library dependency (glibc above all) turns into
       'version GLIBC_2.xx not found' at first pack. build_wbaes.sh builds one statically via a
       HOST_CXX wrapper; re-run it with --force, and do not set HOST_CXX yourself."
        ok "wb_keygen is statically linked (no DT_NEEDED) - portable across Linux distros"
        KEYGEN_LINKAGE="static"
    fi

    # 5. CAPABILITY probe, not an existence check - the same reasoning as build_wbaes.sh:188.
    #    A cached pre-3.0.0 wb_keygen survives an SDK upgrade and seals a heavy/v3 blob that
    #    only misbehaves on device. Verified through the packer's OWN parser so the offsets
    #    cannot drift from provision.py.
    if ! "$WBKEYGEN" --key 000102030405060708090a0b0c0d0e0f --pass p --seed 1 \
            --kdf light --out "$TMP/probe.blob" >"$TMP/probe.log" 2>&1; then
        if grep -qE -- '--kdf|unknown arg' "$TMP/probe.log"; then
            die "$WBKEYGEN is a STALE PRE-3.0.0 host wb_keygen: it rejects --kdf. sopack seals
       at the light tier and requires whitebox-cryptography >= 3.0.0. Rebuild it
       (./scripts/build_wbaes.sh --force) before bundling it."
        fi
        tail -5 "$TMP/probe.log" >&2
        die "$WBKEYGEN does not run on this host (an Android build cannot) - so it would not run
       on the receiving Mac either. Rebuild it with ./scripts/build_wbaes.sh --force."
    fi
    ( cd "$SOPACK" && python3 -c '
import sys
from sopack.provision import assert_light_blob
assert_light_blob(open(sys.argv[1], "rb").read(), tool=sys.argv[2])
' "$TMP/probe.blob" "$WBKEYGEN" ) \
        || die "$WBKEYGEN accepted --kdf but did not produce a v>=4 light-tier blob (above).
       Do not bundle it."
    # file(1) is the nicest description but is genuinely absent from slim containers, and
    # "unknown" in the provenance record of the one host-specific file is a poor consolation.
    # readelf is already required above on Linux, so derive something equivalent from it.
    KEYGEN_DESC="$(file -b "$WBKEYGEN" 2>/dev/null || true)"
    if [ -z "$KEYGEN_DESC" ] && have readelf; then
        KEYGEN_DESC="$(readelf -h "$WBKEYGEN" 2>/dev/null \
            | awk -F: '/Class|Type|Machine/ {gsub(/^ +| +$/,"",$2); printf "%s ", $2}')"
        KEYGEN_DESC="${KEYGEN_DESC% } ($KEYGEN_LINKAGE)"
    fi
    [ -n "$KEYGEN_DESC" ] || KEYGEN_DESC="unknown"
    ok "wb_keygen seals a v>=4 light-tier blob: $WBKEYGEN"
fi

# 6. Build markers. A stale skeleton is undiagnosable on device - the ctor requires an exact
#    region-version match, finds none, and aborts with no explanation - so the marker is the
#    only thing that turns a mismatch into a visible error. Checked here AND recorded in the
#    manifest, so install.sh can re-check it against the rt_meta it just installed. That check is
#    near-tautological now that both ship in one wheel - which is the point; it used to be the
#    only thing standing between a stale skeleton and an unexplained abort on device.
( cd "$SOPACK" && python3 - "$SKEL" "$PROV" <<'PY'
import sys
from sopack.rt_meta import HELPER_BUILD_MARKER, PROVIDER_BUILD_MARKER, REGION_VERSION
for path, marker, src in ((sys.argv[1], HELPER_BUILD_MARKER, 'stub/sopk_rt.c'),
                          (sys.argv[2], PROVIDER_BUILD_MARKER, 'stub/sopk_wb.c')):
    if marker not in open(path, 'rb').read():
        sys.exit(f"ERROR: {path} lacks the v{REGION_VERSION} build marker ({marker.hex()}) - "
                 f"it was built from an older {src}. sopack would refuse it at pack time, so "
                 f"bundling it would ship a brick.")
PY
) || exit 1
ok "both skeletons carry the v$(cd "$SOPACK" && python3 -c 'from sopack.rt_meta import REGION_VERSION; print(REGION_VERSION)') build markers"

# ---- provenance ------------------------------------------------------------------------
# Read before the wheel is built, not just before MANIFEST.txt: the wheel's PEP 440 local version
# is derived from SOPACK_REV, so `pip show sopack` on the receiving machine names the bundle.
SOPACK_REV="$(git -C "$SOPACK" rev-parse --short HEAD 2>/dev/null || echo unknown)"
[ -n "$(git -C "$SOPACK" status --porcelain 2>/dev/null)" ] && SOPACK_REV="$SOPACK_REV-dirty"
# Not `|| echo unknown`. A bundle whose MANIFEST cannot say which white-box built it is a
# provenance hole, and it used to open silently whenever $WBC was not a readable git repo.
WBC_REV="$(git -C "$WBC" rev-parse --short HEAD 2>/dev/null || true)"
[ -n "$WBC_REV" ] || die "cannot read a git revision from $WBC, so MANIFEST.txt could not
       record which whitebox-cryptography built this bundle. Use the pinned submodule
       (git submodule update --init $WBC_SUBMODULE) rather than an unpacked copy."
# A bundle cut from an experimental WBC must not look identical to a pinned build. TWO ways to
# be off-pin, and only the first is what `git submodule status` reports:
#   1. the submodule itself is checked out somewhere else  -> status prefixes '+'
#   2. --wbc/$WBC points at a DIFFERENT tree entirely      -> status says nothing, because the
#      untouched submodule is still at its pin. Checking only (1) would miss the commoner case.
# Compare resolved paths, not strings: --wbc can name the submodule by a relative or
# symlinked path, and a spurious "-external" on a pinned build is a false alarm nobody would
# trust twice.
WBC_REAL="$(cd "$WBC" 2>/dev/null && pwd -P || echo "$WBC")"
SUB_REAL="$(cd "$SOPACK/$WBC_SUBMODULE" 2>/dev/null && pwd -P || echo "$SOPACK/$WBC_SUBMODULE")"
if [ "$WBC_REAL" != "$SUB_REAL" ]; then
    WBC_REV="$WBC_REV-external"
    warn "building against $WBC, not the pinned submodule; recording wbc-rev: $WBC_REV"
else
    case "$(git -C "$SOPACK" submodule status "$WBC_SUBMODULE" 2>/dev/null)" in
        "+"*) WBC_REV="$WBC_REV-unpinned"
              warn "the whitebox-cryptography submodule is NOT at its pinned commit; recording
      wbc-rev: $WBC_REV" ;;
    esac
fi
LIEF_VER="$(cd "$SOPACK" && python3 -c 'import lief; print(lief.__version__)' 2>/dev/null \
            || echo unknown)"
eval "$(cd "$SOPACK" && python3 -c 'from sopack import rt_meta as m; print(
    "REGION_VERSION=%d\nHELPER_MARKER=%s\nPROVIDER_MARKER=%s\nPROVIDER_SONAME=%s" % (
    m.REGION_VERSION, m.HELPER_BUILD_MARKER.hex(), m.PROVIDER_BUILD_MARKER.hex(),
    m.PROVIDER_SONAME))')"

# ---- the wheel: ship the TOOL, not just its artifacts ----------------------------------
# Earlier bundles carried only Android artifacts and told the receiving machine to `git clone`
# sopack and `pip install -e .` - the one thing a machine without source code cannot do. So the
# tool travels as a py3-none-any wheel (sopack is pure Python; lief is its only dependency) with
# the two GATED skeletons baked in as package data.
#
# Built from a STAGED copy in $TMP, never from $SOPACK, for two independent reasons:
#   1. package-data globs stubs/*.so. A build from the repo would sweep in skeletons for ABIs no
#      gate above ever inspected - every gate runs against $SKEL/$PROV, which are two files.
#   2. pyproject.toml must NOT gain stubs/*.so permanently. .gitignore:12-15 calls those a local
#      artifact, not package data, and flipping that globally would let any `pip install .` embed
#      whatever happens to sit in sopack/stubs/ - including the --trace build that device_test.sh
#      writes to those exact paths and that gate 3 exists to refuse.
# The package-data line is therefore an OVERLAY on the staged tree: "a wheel with skeletons in it"
# stays a gated output of this script rather than something anyone can produce by accident.
say "building the sopack wheel"
python3 -m pip --version >/dev/null 2>&1 \
    || die "python3 -m pip is unavailable, so the wheel cannot be built. The wheel IS the tool as
       far as the receiving machine is concerned, so there is no useful bundle without it."

WSRC="$TMP/wheelsrc"
mkdir -p "$WSRC/sopack/stubs"
cp "$SOPACK/pyproject.toml" "$WSRC/"
cp "$SOPACK"/sopack/*.py "$WSRC/sopack/"
cp "$STUBDIR"/stub_*.bin "$STUBDIR"/stub_*.json "$WSRC/sopack/stubs/"
cp "$SKEL" "$PROV" "$WSRC/sopack/stubs/"
STAGED_SO="$(find "$WSRC/sopack/stubs" -name '*.so' | wc -l | tr -d ' ')"
[ "$STAGED_SO" = "2" ] \
    || die "staged $STAGED_SO skeletons, expected exactly 2 (the gated $ABI pair). Something
       copied more than \$SKEL and \$PROV into $WSRC - do not ship skeletons no gate inspected."

# PEP 440 local version: alphanumerics separated by dots, nothing else. SOPACK_REV is
# "<sha>-dirty" on a dirty tree and every ABI name has a hyphen, so both must be sanitised or
# `pip wheel` fails with an invalid-version error that says nothing about this script.
WHEEL_LOCAL="$(printf '%s.api%s.%s' "$(printf '%s' "$ABI" | tr -d '-')" "$API" "$SOPACK_REV" \
               | tr -c '[:alnum:]' '.' | sed 's/\.\{2,\}/./g; s/^\.//; s/\.$//')"
python3 - "$WSRC/pyproject.toml" "$WHEEL_LOCAL" <<'PY' || exit 1
import re, sys
path, local = sys.argv[1], sys.argv[2]
src = open(path).read()

src, n = re.subn(r'(?m)^(version = "[^"+]+)"', lambda m: '%s+%s"' % (m.group(1), local), src, 1)
if n != 1:
    sys.exit('ERROR: no `version = "..."` line in the staged pyproject.toml to tag')

# Tolerant of formatting, because the point is to notice when the real file changes shape rather
# than to silently no-op: locate the package-data list itself and append to it.
m = re.search(r'(?ms)^\[tool\.setuptools\.package-data\]\s*\nsopack\s*=\s*\[(.*?)\]', src)
if not m:
    sys.exit('ERROR: no [tool.setuptools.package-data] sopack = [...] block in pyproject.toml - '
             'the overlay cannot be applied, and a wheel without the skeletons in it is useless '
             'to the receiving machine.')
if '*.so' not in m.group(1):
    src = src[:m.end(1)] + ', "stubs/*.so"' + src[m.end(1):]
open(path, 'w').write(src)
PY

WHEELDIR="$TMP/wheel"
mkdir -p "$WHEELDIR"
# Isolated build first (it is what a release build should do), falling back to the local backend:
# isolation downloads setuptools from PyPI, and this script is otherwise happy offline.
if ! python3 -m pip wheel "$WSRC" --no-deps -w "$WHEELDIR" >"$TMP/wheel.log" 2>&1; then
    warn "isolated wheel build failed (no network for the build backend?) - retrying with
      --no-build-isolation"
    if ! python3 -m pip wheel "$WSRC" --no-deps --no-build-isolation -w "$WHEELDIR" \
            >>"$TMP/wheel.log" 2>&1; then
        tail -30 "$TMP/wheel.log" >&2
        die "could not build the sopack wheel (log above; full log at $TMP/wheel.log)."
    fi
fi
WHEEL="$(find "$WHEELDIR" -maxdepth 1 -name 'sopack-*.whl' | head -1)"
[ -n "$WHEEL" ] || die "pip wheel exited 0 but produced no sopack-*.whl in $WHEELDIR"

# ---- gate 7: the wheel actually carries what the receiving machine will need ------------
# A package-data glob that quietly fails to match produces a wheel that INSTALLS CLEANLY and only
# fails when an APK is packed, with StubMissingError, on the machine that has no toolchain to
# diagnose it. So read the built wheel back rather than trusting the build.
python3 - "$WHEEL" "$SKEL" "$PROV" "$ABI" <<'PY' || exit 1
import sys, zipfile

whl, skel, prov, abi = sys.argv[1:5]
z = zipfile.ZipFile(whl)
names = set(z.namelist())

skel_member, prov_member = 'sopack/stubs/sopk_rt_%s.so' % abi, 'sopack/stubs/sopk_wb_%s.so' % abi
# config.py carries the config loader AND the SAMPLE_YAML that `sopack init-config` writes.
# It is a .py so the `cp "$SOPACK"/sopack/*.py` staging above picks it up - but a wheel that
# lost it would still install cleanly and only fail when the receiving machine packs, which is
# precisely what this gate exists to prevent.
required = [skel_member, prov_member,
            'sopack/cli.py', 'sopack/config.py', 'sopack/stubs.py', 'sopack/rt_meta.py',
            'sopack/provision.py']
for a in ('arm64-v8a', 'armeabi-v7a', 'x86_64'):
    required += ['sopack/stubs/stub_%s.bin' % a, 'sopack/stubs/stub_%s.json' % a]

missing = [n for n in required if n not in names]
if missing:
    sys.exit('ERROR: the wheel is missing %d file(s): %s\n'
             '       package-data in the staged pyproject.toml did not match. A wheel like this\n'
             '       installs cleanly and only fails when the receiving machine packs an APK.'
             % (len(missing), ', '.join(missing)))

# Bytes, not just names: the skeletons in the wheel must be the ones gates 3 and 6 inspected.
for member, path in ((skel_member, skel), (prov_member, prov)):
    if z.read(member) != open(path, 'rb').read():
        sys.exit('ERROR: %s in the wheel differs from the gated %s' % (member, path))

# And nothing else, so an ABI no gate looked at cannot ride along.
extra = sorted(n for n in names
               if n.startswith('sopack/stubs/') and n.endswith('.so') and n not in required)
if extra:
    sys.exit('ERROR: the wheel carries ungated skeletons: %s' % ', '.join(extra))
PY
ok "wheel carries both $ABI skeletons + all six stub blobs: $(basename "$WHEEL")"

# ---- assemble --------------------------------------------------------------------------
say "assembling the bundle in $OUT"
rm -rf "$OUT"
mkdir -p "$OUT/stubs" "$OUT/bin"

# All three ABIs' blobs regardless of --abi: they are 6-8 KB, they are committed, and a
# receiving Mac with `cipher: chacha20` and `abis: all` needs them. --abi governs the skeletons.
for f in "$STUBDIR"/stub_*.bin "$STUBDIR"/stub_*.json; do
    [ -f "$f" ] || die "no stub blobs in $STUBDIR - they are committed package data, so this
       means the checkout is incomplete. Run: bash stub/build_stubs.sh $API"
    cp "$f" "$OUT/stubs/"
done
cp "$SKEL" "$PROV" "$OUT/stubs/"
# The wheel goes in the bundle ROOT, not beside it like the tarball: install.sh verifies
# SHA256SUMS before it installs anything, and the `find . -type f` below picks the wheel up for
# free only if it is already in place. Installing an unverified wheel would defeat that check.
cp "$WHEEL" "$OUT/"
WHEEL_NAME="$(basename "$WHEEL")"

# ---- the bundle's own config.yaml -------------------------------------------------------
# The FULL commented config, not a stub. The receiving machine has no checkout, so a two-key
# file that says "run sopack init-config to see the rest" is telling the one reader who
# cannot easily get to the rest. This ships the same file `sopack init-config` writes, with
# the two bundle-specific values substituted in.
#
# Those two, and only those two, cannot be left at their defaults:
#
#   abis:   a bundle carries ONE ABI's wbaes skeletons. sopack's default is arm64-v8a, so an
#           x86_64 bundle left on the defaults fails at pack time with StubMissingError.
#   cipher: an --allow-foreign-host bundle carries no bin/wb_keygen, so the default wbaes
#           cannot seal a blob at all.
#
# Generated from sopack.config.SAMPLE_YAML rather than copied from the checkout's
# config.sample.yaml: the receiving machine installs the WHEEL, so the config has to match
# what the wheel carries, not what happens to be lying in the source tree.
#
# Written BEFORE the SHA256SUMS pass below, which sweeps `find . -type f`, so it is covered.
if [ "$WITH_KEYGEN" -eq 1 ]; then
    BUNDLE_CIPHER="wbaes"
    BUNDLE_CIPHER_NOTE="wbaes is the default and this bundle carries bin/wb_keygen, which
# sopack finds on its own - nothing to export, nothing to configure."
else
    BUNDLE_CIPHER="chacha20"
    BUNDLE_CIPHER_NOTE="NOT the default: this bundle was generated with --allow-foreign-host,
# so it carries no bin/wb_keygen and cipher: wbaes cannot seal a blob here. Regenerate the
# bundle on macOS or Linux/x86_64 for white-box support."
fi
# Absolute dest, because the generator runs from $SOPACK: `import sopack` resolves from the
# repo root (the preflight above checks it exactly that way), but --out may be relative and
# would then land somewhere else entirely.
BUNDLE_CFG="$(cd "$OUT" && pwd)/config.yaml"
( cd "$SOPACK" && python3 - "$BUNDLE_CFG" "$BUNDLE_CIPHER" "$ABI" "$BUNDLE_CIPHER_NOTE" <<'PY'

import re, sys
from sopack.config import SAMPLE_YAML, loads

dest, cipher, abi, cipher_note = sys.argv[1:5]

header = (
    "# sopack configuration for THIS bundle.\n"
    "#\n"
    "#   sopack pack <your.apk> -o packed.apk --config <this file>\n"
    "#\n"
    "# This is the complete, commented config - the same file `sopack init-config` writes,\n"
    "# with two values pinned to what this bundle can actually do (marked BUNDLE-PINNED\n"
    "# below). Everything else is at its default. Edit any of it.\n"
    "\n"
)

# Anchored, and the replacement COUNT is checked: the sample's prose names every cipher and
# every ABI in comments, and on the default arm64-v8a + keygen bundle the intended values are
# identical to the sample's own defaults - so a parse-back alone could not tell a working
# substitution from one that matched nothing. Only the count can.
text, n = re.subn(r'(?m)^cipher: wbaes$',
                  '# BUNDLE-PINNED: %s\ncipher: %s' % (cipher_note, cipher),
                  SAMPLE_YAML)
if n != 1:
    sys.exit("ERROR: expected exactly one 'cipher: wbaes' line in SAMPLE_YAML, matched %d.\n"
             "       sopack/config.py's sample changed shape and this substitution no longer\n"
             "       finds it - the bundle would ship an unpinned config." % n)

text, n = re.subn(r'(?m)^  - arm64-v8a$', '  - %s' % abi, text)
if n != 1:
    sys.exit("ERROR: expected exactly one '  - arm64-v8a' list entry in SAMPLE_YAML, matched "
             "%d.\n       The abis: block changed shape; the bundle would ship the wrong ABI."
             % n)

text = header + text

# Parse it back with sopack's own loader: catches a substitution that matched but produced
# something the packer will reject, which would otherwise surface at first pack.
cfg = loads(text, dest)
if cfg.cipher != cipher or list(cfg.abis) != [abi]:
    sys.exit("ERROR: the generated bundle config parses as cipher=%s abis=%s, wanted %s / [%s]"
             % (cfg.cipher, list(cfg.abis), cipher, abi))

open(dest, "w").write(text)
PY
) || die "could not generate the bundle's config.yaml (see the error above)"
ok "bundle config.yaml: full sample, cipher=$BUNDLE_CIPHER abis=$ABI ($(grep -c . "$BUNDLE_CFG") non-blank lines)"
if [ "$WITH_KEYGEN" -eq 1 ]; then
    cp "$WBKEYGEN" "$OUT/bin/wb_keygen"
    chmod +x "$OUT/bin/wb_keygen"
else
    rmdir "$OUT/bin"
fi

cat >"$OUT/MANIFEST.txt" <<EOF
# sopack portable pack bundle. Generated by scripts/artifact_generation.sh - do not hand-edit;
# install.sh reads these fields back and refuses on a mismatch.
bundle-format: $BUNDLE_FORMAT
generated-utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
sopack-rev: $SOPACK_REV
wbc-rev: $WBC_REV
lief-version: $LIEF_VER
host-os: $HOST_OS
host-arch: $HOST_ARCH
abi: $ABI
api: $API
wheel: $WHEEL_NAME
skeleton-build: release
region-version: $REGION_VERSION
helper-build-marker: $HELPER_MARKER
provider-build-marker: $PROVIDER_MARKER
provider-soname: $PROVIDER_SONAME
provider-obfuscation: $PROVIDER_OBFUSCATION
wb-keygen: $KEYGEN_DESC
wb-keygen-linkage: $KEYGEN_LINKAGE
EOF

# ---- install.sh (runs on the receiving machine) ----------------------------------------
# Quoted heredoc: nothing here is interpolated from THIS host. Everything it needs to know it
# reads back out of MANIFEST.txt, so the two can never disagree.
cat >"$OUT/install.sh" <<'INSTALL_SH'
#!/usr/bin/env bash
#
# install.sh - install sopack from this bundle onto THIS machine.
#
# This bundle carries the TOOL (sopack-*.whl, with this ABI's wbaes skeletons baked in as package
# data) plus the one host-specific binary, bin/wb_keygen. There is nothing to clone: no sopack
# checkout, no NDK, no whitebox-cryptography.
#
# By default it creates a virtualenv beside this script, installs the wheel into it, and then
# verifies that the install can actually reach its own skeletons. pip needs network once, to
# fetch sopack's dependencies (lief and pyyaml).
#
# Usage:
#   ./install.sh                 # venv at ./venv, install the wheel, verify
#   ./install.sh --python PATH   # build the venv from a specific interpreter
#   ./install.sh --no-venv       # install into `python3 -m pip` instead (PEP 668 applies)
#   ./install.sh --no-keygen     # skip bin/wb_keygen; chacha20/xor packing only
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    OK: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

NO_KEYGEN=0
USE_VENV=1
PYTHON=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --no-keygen)  NO_KEYGEN=1; shift ;;
        --no-venv)    USE_VENV=0; shift ;;
        --python)     PYTHON="$2"; shift 2 ;;
        # 2..17 is the header block, ending just before `set -euo pipefail`.
        -h|--help)    sed -n '2,17p' "$0"; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -f "$HERE/MANIFEST.txt" ] || die "no MANIFEST.txt beside $0 - this is not a sopack bundle"
man() { sed -n "s/^$1: //p" "$HERE/MANIFEST.txt" | head -1; }

[ "$(man bundle-format)" = "2" ] \
    || die "bundle-format $(man bundle-format) is not 2 - this bundle was made by a different
       artifact_generation.sh than the install script expects. Format 1 bundles carried no wheel
       and installed by copying into an existing sopack checkout; regenerate the bundle."

say "bundle $(man sopack-rev), $(man abi) / android-$(man api), built $(man generated-utc)"

# Surface this at INSTALL time, not just in MANIFEST.txt. It is a property of the artifacts the
# bundle already contains - nothing here can fix it - and the person installing is usually not
# the person who generated it, so the manifest alone would go unread.
case "$(man provider-obfuscation)" in
    none)    warn "this bundle's libsopk_wb.so was built WITHOUT O-MVLL
      (--allow-unobfuscated-provider). The provider carries the sealed white-box blob and every
      wbc_* call, so it is the artifact whose static-analysis resistance matters most. Packing
      works normally; the hardening is weaker. Regenerate on a host where the plugin loads." ;;
    unknown) warn "this bundle was generated with --skip-build, so whether libsopk_wb.so is
      obfuscated is unrecorded - a shared object carries no such state. Regenerate without
      --skip-build if this is a release bundle." ;;
esac

# 1. Host match. Only bin/wb_keygen is host-specific, so this check is only about that file:
#    a bundle generated with --allow-foreign-host has none, and installs anywhere.
WANT_OS="$(man host-os)"; WANT_ARCH="$(man host-arch)"
HAVE_OS="$(uname -s)";    HAVE_ARCH="$(uname -m)"
if [ ! -f "$HERE/bin/wb_keygen" ]; then
    [ "$WANT_OS/$WANT_ARCH" = "$HAVE_OS/$HAVE_ARCH" ] \
        || info "built on $WANT_OS/$WANT_ARCH; everything in it is host-neutral"
elif [ "$WANT_OS/$WANT_ARCH" != "$HAVE_OS/$HAVE_ARCH" ] && [ "$NO_KEYGEN" -eq 0 ]; then
    die "this bundle's bin/wb_keygen was built on $WANT_OS/$WANT_ARCH and this host is
       $HAVE_OS/$HAVE_ARCH, so it will not execute here. Everything else in the bundle is either
       pure Python or an Android target ELF and is host-neutral: re-run with --no-keygen to
       install those, then pack with cipher: chacha20 (or build a host wb_keygen from a sopack
       checkout with ./scripts/build_wbaes.sh)."
fi

# 2. Checksums. BEFORE anything is installed - the wheel is inside the bundle, and installing an
#    unverified wheel would make this check decorative.
if   command -v shasum    >/dev/null 2>&1; then SHA="shasum -a 256"
elif command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"
else SHA=""
fi
if [ -n "$SHA" ] && [ -f "$HERE/SHA256SUMS" ]; then
    ( cd "$HERE" && $SHA -c SHA256SUMS >/dev/null ) \
        || die "SHA256SUMS does not verify - the bundle is corrupt or was edited in place"
    ok "checksums verify"
else
    warn "no shasum/sha256sum on PATH - skipping the integrity check"
fi

# 3. Install the wheel.
WHEEL="$(man wheel)"
[ -n "$WHEEL" ] || die "MANIFEST.txt names no wheel - this bundle carries no tool to install"
[ -f "$HERE/$WHEEL" ] || die "MANIFEST.txt names $WHEEL but it is not in this bundle"

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || die "no '$PY' on PATH - pass --python /path/to/python3"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
    || die "$PY is $("$PY" -V 2>&1); sopack needs Python >= 3.9. Pass --python PATH."

if [ "$USE_VENV" -eq 1 ]; then
    # The venv is not tidiness. Homebrew's python3 on macOS is externally managed (PEP 668), so a
    # bare `pip install ./sopack-*.whl` dies with "error: externally-managed-environment" - a
    # message that never mentions sopack. A fresh venv also cannot contain a competing editable
    # sopack from an old checkout, which is the one way this install can appear to work and do
    # nothing.
    VENVDIR="$HERE/venv"
    if [ ! -x "$VENVDIR/bin/python" ]; then
        "$PY" -m venv "$VENVDIR" || die "'$PY -m venv' failed. On Debian/Ubuntu: apt install
       python3-venv. On macOS both python.org and Homebrew python3 ship it."
    fi
    RUNPY="$VENVDIR/bin/python"
    SOPACK_CMD="$VENVDIR/bin/sopack"
    info "virtualenv: $VENVDIR"
else
    RUNPY="$PY"
    SOPACK_CMD="$PY -m sopack.cli"
    warn "--no-venv: installing into $PY. If that interpreter is externally managed (PEP 668)
      pip will refuse, and an editable sopack already installed there will shadow this one."
fi

say "installing $WHEEL (pip fetches lief + pyyaml from PyPI - this step needs network once)"
# Two calls on purpose. The first resolves dependencies (lief, pyyaml) on a fresh environment. The second
# forces THESE bytes into place with no download: the wheel version only changes with the git
# rev, so re-installing a regenerated bundle at the same rev would otherwise be "already
# satisfied" and leave the OLD skeletons installed - the stale-artifact failure this bundle
# exists to prevent, and one that is invisible until the packed app aborts on device.
"$RUNPY" -m pip install "$HERE/$WHEEL" || die "pip install failed (output above)"
"$RUNPY" -m pip install --force-reinstall --no-deps "$HERE/$WHEEL" \
    || die "pip re-install failed (output above)"

# The console script is written by the installer, and a force-reinstall is an uninstall followed
# by an install - which is exactly where an entry-point script can go missing. Every recipe below
# (and in README.md) points at it, so check rather than assume.
if [ "$USE_VENV" -eq 1 ]; then
    [ -x "$SOPACK_CMD" ] || die "the wheel installed but $SOPACK_CMD does not exist. Use
       '$RUNPY -m sopack.cli' instead, and report this - the bundle's README points at the
       console script."
fi

# 4. Post-install probe. This replaces the region-version/build-marker cross-check that format-1
#    bundles ran against a sopack CHECKOUT. The tool and the skeletons now ship inside one wheel,
#    so they cannot drift from each other; what can still go wrong is that the install is not
#    what gets imported, or that the wheel did not carry what we think. Both are silent until an
#    APK is packed on a machine with no toolchain to debug it.
WANT_KEYGEN=0
if [ "$NO_KEYGEN" -eq 0 ] && [ -f "$HERE/bin/wb_keygen" ]; then WANT_KEYGEN=1; fi
"$RUNPY" - "$(man abi)" "$(man region-version)" "$(man helper-build-marker)" \
             "$(man provider-build-marker)" "$(man lief-version)" \
             "$WANT_KEYGEN" "$HERE" <<'PY'
import os, sys

abi, want_ver, want_h, want_p, want_lief, want_keygen, bundle = sys.argv[1:8]

try:
    import sopack
    import sopack.rt_meta as m
    import sopack.stubs as s
except Exception as e:
    sys.exit("ERROR: cannot import sopack after installing it: %s" % e)

pkg = os.path.dirname(os.path.abspath(sopack.__file__))
if 'site-packages' not in pkg.split(os.sep):
    sys.exit(
        "ERROR: `import sopack` resolves to %s, which is not an installed package. Something\n"
        "       else - almost certainly an editable install from an old sopack checkout on this\n"
        "       machine - is shadowing the wheel, so the skeletons this bundle carries would\n"
        "       never be read. Re-run without --no-venv, or `pip uninstall sopack` there first."
        % pkg)

# Reachable, not merely present in the zip: this is the check that catches a package-data glob
# that silently did not match, which otherwise surfaces as StubMissingError at pack time.
try:
    s.provider_skeleton_path(abi)
    s.helper_skeleton_path(abi)
    for a in s.SUPPORTED_ABIS:
        s.load_stub(a)
except Exception as e:
    sys.exit("ERROR: the installed sopack cannot reach its own artifacts: %s" % e)

# The keygen is DISCOVERED, not configured: wbaes is the default cipher and there is neither a
# --wb-keygen flag nor a config key for it, so provision.find_wb_keygen has to resolve this bundle's
# bin/wb_keygen on its own (via sys.prefix's parent, guarded by the sibling MANIFEST.txt).
# If that probe misses, the install still looks perfect and the FIRST PACK fails - on the
# machine least equipped to debug it. So resolve it here, while the bundle is still in hand.
if want_keygen == '1':
    from sopack.provision import find_wb_keygen
    try:
        found = find_wb_keygen()
    except Exception as e:
        sys.exit("ERROR: sopack cannot find this bundle's bin/wb_keygen, so cipher: wbaes\n"
                 "       (the default) would fail at pack time: %s" % e)
    if os.path.realpath(found) != os.path.realpath(os.path.join(bundle, 'bin', 'wb_keygen')):
        sys.exit("ERROR: sopack resolved wb_keygen to %s, not this bundle's %s.\n"
                 "       Something else on this machine is winning the probe; packing would\n"
                 "       seal with an unknown tool. Unset SOPACK_WBKEYGEN and re-run."
                 % (found, os.path.join(bundle, 'bin', 'wb_keygen')))
    print("    OK: wb_keygen discovered at %s" % found)

have = (want_ver, want_h, want_p) == (str(m.REGION_VERSION), m.HELPER_BUILD_MARKER.hex(),
                                      m.PROVIDER_BUILD_MARKER.hex())
if not have:
    sys.exit(
        "ERROR: MANIFEST.txt says region v%s (helper %s, provider %s) but the sopack just\n"
        "       installed is v%d (helper %s, provider %s). The bundle was assembled from\n"
        "       mismatched parts - regenerate it; this pair would abort on device with no\n"
        "       explanation." % (want_ver, want_h, want_p, m.REGION_VERSION,
                                 m.HELPER_BUILD_MARKER.hex(), m.PROVIDER_BUILD_MARKER.hex()))

# lief is the one dependency install.sh does not control - pip resolved it just now. A Python
# newer than any published lief wheel makes pip fall back to a source build that either takes a
# very long time or dies in a compiler error naming neither lief nor sopack.
try:
    import lief
except Exception as e:
    sys.exit(
        "ERROR: lief did not install: %s\n"
        "       sopack cannot do any ELF surgery without it. If pip tried to BUILD it, this\n"
        "       interpreter (Python %d.%d) is newer than any published lief wheel: re-run as\n"
        "       ./install.sh --python /path/to/python3.11"
        % (e, sys.version_info[0], sys.version_info[1]))
# pyyaml is the other dependency pip resolved just now, and it is not optional: every setting
# except the input and output APK comes from a config file, so without it `sopack pack` cannot
# read its own configuration. Same class of failure as lief - invisible until the first pack.
try:
    import yaml
except Exception as e:
    sys.exit(
        "ERROR: pyyaml did not install: %s\n"
        "       sopack reads all of its settings from a YAML config file, so it cannot pack\n"
        "       without it. Re-run install.sh with network available." % e)

if want_lief not in ('', 'unknown', lief.__version__):
    print("    WARN: lief %s here, %s on the machine that generated this bundle. The >=1.0 floor\n"
          "          is what matters (0.17.0 emitted 4 KB-aligned LOAD segments sopack refuses)."
          % (lief.__version__, want_lief), file=sys.stderr)

print("    OK: sopack installed at %s" % pkg)
print("    OK: %s skeletons reachable, region v%d, lief %s"
      % (abi, m.REGION_VERSION, lief.__version__))
PY

if [ "$NO_KEYGEN" -eq 1 ] || [ ! -f "$HERE/bin/wb_keygen" ]; then
    cat <<EOF

==> Installed. This bundle has no usable wb_keygen here, so it cannot seal a white-box blob.
    Its config.yaml already pins cipher: chacha20 for that reason - pack with it:

  $SOPACK_CMD pack <your.apk> -o packed.apk --config "$HERE/config.yaml"

  The raw key then ships in the binary (whitened), not sealed in a white-box.

EOF
    exit 0
fi

chmod +x "$HERE/bin/wb_keygen"
cat <<EOF

==> Installed. Pack - this bundle's config.yaml pins cipher: wbaes and abis: [$(man abi)], and
    sopack finds this bundle's bin/wb_keygen on its own (the probe above just confirmed it):

  $SOPACK_CMD pack <your.apk> -o packed.apk --config "$HERE/config.yaml"

  Everything except the input and output APK is configured in that file, and it selects every
  lib/$(man abi)/*.so in the APK by default. It is the COMPLETE commented config - every option
  is in there with an explanation, so open it rather than hunting for docs. Edit it to name
  libraries, add exclusions, point at your own keystore or turn the signature dump off.

  This bundle carries wbaes skeletons for $(man abi) ONLY, which is why config.yaml pins that
  ABI. The stub blobs cover all three, so a chacha20/xor config can widen \`abis:\`, but wbaes
  on another ABI fails with a StubMissingError at pack time - regenerate the bundle per ABI if
  you need another.
  See README.md in this bundle for the tools you still need on this machine (JDK, apksigner).
EOF
INSTALL_SH
chmod +x "$OUT/install.sh"

# ---- README.md -------------------------------------------------------------------------
# The quick-start used to print a wbaes recipe unconditionally, including in an
# --allow-foreign-host bundle that carries no wb_keygen and therefore cannot run the default
# cipher at all. Now that wbaes IS the default, that would be a recipe that fails on the first
# try, so the two cases diverge here.
if [ "$WITH_KEYGEN" -eq 1 ]; then
    KEYGEN_RECIPE_NOTE="This bundle's \`config.yaml\` pins \`cipher: wbaes\` and \`abis: [$ABI]\`;
signature verification is on by default. sopack locates this bundle's \`bin/wb_keygen\` itself -
nothing to export, nothing to configure."
else
    KEYGEN_RECIPE_NOTE="**This bundle's \`config.yaml\` pins \`cipher: chacha20\`, and that is not
optional here.** It was generated with \`--allow-foreign-host\`, so it carries no
\`bin/wb_keygen\` and the default cipher (\`wbaes\`) cannot seal a blob. Regenerate the bundle on
macOS or Linux/x86_64 for white-box support."
fi
# Each recipe below passes --config with ITS OWN path to the bundle's config.yaml rather than
# relying on the ./config.yaml lookup: the user unpacks the bundle somewhere and packs from
# wherever they happen to be, so the CWD is not the bundle. That is why this is spelled out per
# recipe instead of being one shared suffix variable - the three recipes reach the bundle by
# three different paths.

# The provider's obfuscation state is a property of the shipped artifact, so it belongs in the
# bundle's own README rather than only in the generating repo's logs.
case "$PROVIDER_OBFUSCATION" in
    omvll) PROVIDER_NOTE="\`libsopk_wb.so\` was built **with O-MVLL**, which is what the default
generation path does." ;;
    none)  PROVIDER_NOTE="> **This provider is UNOBFUSCATED.** The bundle was generated with
> \`--allow-unobfuscated-provider\`, so \`libsopk_wb.so\` was built without O-MVLL. It carries the
> sealed white-box blob and every \`wbc_*\` call, so it is the artifact whose static-analysis
> resistance matters most. Packing behaves normally and the white-box still protects the
> long-term key; what is weaker is how quickly the design can be read off the binary." ;;
    *)     PROVIDER_NOTE="> **Provider obfuscation is unrecorded.** This bundle was generated with
> \`--skip-build\`, and a shared object carries no obfuscation state, so nothing can say after
> the fact whether \`libsopk_wb.so\` went through O-MVLL. Regenerate without \`--skip-build\` if
> this is a release bundle." ;;
esac

# Unquoted heredoc so $ABI etc. interpolate; every literal dollar below is escaped.
cat >"$OUT/README.md" <<EOF
# sopack portable pack bundle

This bundle is self-contained: it carries **the tool** (\`$WHEEL_NAME\`) as well as the
artifacts it needs. Everything in it is host-neutral - pure Python, or an **Android target ELF**
that does not care which machine packed it - except the single binary \`bin/wb_keygen\`, which is
why the bundle is pinned to $HOST_OS/$HOST_ARCH: see \`MANIFEST.txt\`.

Generated from sopack \`$SOPACK_REV\` for \`$ABI\` / android-$API.

## Install

\`\`\`bash
cd /path/to/this/bundle && ./install.sh
./venv/bin/sopack pack <your.apk> -o packed.apk --config ./config.yaml
\`\`\`

${KEYGEN_RECIPE_NOTE}

\`install.sh\` verifies the checksums, checks that this host can run \`bin/wb_keygen\`, creates a
virtualenv at \`./venv\`, installs the wheel into it, and then verifies that the installed sopack
can actually reach its own skeletons. **There is no repository to clone.**

The virtualenv is not tidiness: Homebrew's \`python3\` on macOS is externally managed (PEP 668),
so installing the wheel into it directly fails with \`error: externally-managed-environment\`.
Useful flags: \`--python PATH\` (build the venv from a specific interpreter), \`--no-venv\`
(install into \`python3 -m pip\` anyway), \`--no-keygen\` (skip \`bin/wb_keygen\` on a host that
cannot run it - you still get \`cipher: chacha20\`).

## What you still need on this machine

| Dependency | Why | Required? |
|---|---|---|
| Python >= 3.9 with \`venv\` | runs the tool; \`install.sh\` builds the venv with it | **yes** |
| **Network, once** | \`pip\` fetches \`lief\` while installing the wheel. Nothing else is downloaded | **yes**, at install time only |
| A **JDK** (\`keytool\`, \`java\`) | \`keytool\` runs on your **first pack even with no keystore configured** - sopack generates \`~/.sopack/debug.keystore\`. \`java\` is needed when apksigner resolves to a \`.jar\` | **yes**, every cipher |
| \`apksigner\` | signs the repackaged APK, and backs \`signing.verify\` | **yes**. Found on PATH, under \`\$ANDROID_SDK_ROOT\`/\`\$ANDROID_HOME\` \`build-tools/*\`, or via \`\$SOPACK_APKSIGNER_JAR\` |
| \`bin/wb_keygen\` (in this bundle) | seals the white-box blob at pack time | \`cipher: wbaes\` (the DEFAULT) only. Found automatically - it sits beside the venv \`install.sh\` creates, and sopack probes there |
| \`zipalign\` | 16 KB alignment of the output APK | optional - sopack falls back to a pure-Python aligner |
| \`openssl\` | fast ChaCha20 / AES-CTR | optional - pure-Python fallback runs at ~0.6 MB/s, so a multi-MB \`.text\` is slow but correct |

\`lief >= 1.0\` is a **hard floor**, pinned in the wheel's metadata so pip enforces it: 0.17.0
emitted 4 KB-aligned LOAD segments that fail sopack's 16 KB check.

**Not needed**, which is the whole point: **the sopack git repository**, the Android NDK, cmake,
ninja, a whitebox-cryptography checkout, or \`aapt\`. Those produced \`stubs/*\` on the generating
machine, and their output travels inside the wheel.

## Contents

| Path | Host-neutral? | What |
|---|---|---|
| \`$WHEEL_NAME\` | yes | **the tool**, pure Python. Carries the \`$ABI\` skeletons + all three ABIs' stub blobs as package data - which is why its version carries the \`+$WHEEL_LOCAL\` local tag naming the ABI, API level and sopack revision it was cut from. \`pip show sopack\` on this machine reads it back |
| \`stubs/stub_*.bin\`, \`stubs/stub_*.json\` | yes | freestanding stub blobs for all three ABIs (\`cipher: chacha20\`/\`xor\`), as loose copies |
| \`stubs/sopk_wb_$ABI.so\` | yes | the shared white-box provider, one per ABI. Obfuscation: **$PROVIDER_OBFUSCATION** |
| \`stubs/sopk_rt_$ABI.so\` | yes | the thin per-target helper skeleton the packer clones |
| \`bin/wb_keygen\` | **no** | host provisioning tool, $HOST_OS/$HOST_ARCH; linkage **$KEYGEN_LINKAGE** |
| \`config.yaml\` | yes | **the pack settings, fully commented.** Every option with an explanation - this file is the documentation. Two values are pinned to this bundle (\`cipher: $BUNDLE_CIPHER\`, \`abis: [$ABI]\`), marked BUNDLE-PINNED; the rest is at its default. Edit it in place |
| \`MANIFEST.txt\` | - | provenance; \`install.sh\` reads it back |
| \`SHA256SUMS\` | - | integrity, over every file including the wheel |

\`stubs/\` duplicates what is already inside the wheel. It is kept because it is a few hundred KB
and it is what you diff, checksum or hand to someone debugging a device failure - the installed
copy lives inside \`venv/\` where nobody looks.

Both skeletons are **release** builds: no logcat tracing, so a failure at load is a silent
SIGABRT by design. If a packed app crashes on device, rebuild with
\`./scripts/build_wbaes.sh --trace\` on the generating machine and pack with
\`logging.allow-helper-log: true\` in your config to find out why - do not ship that build.

${PROVIDER_NOTE}

To regenerate this bundle: \`./scripts/artifact_generation.sh\` in the sopack repo.
EOF

# SHA256SUMS last, and over everything else - relative paths, so it verifies from any location.
# One invocation per file rather than xargs: it costs nothing at this file count and survives a
# path with a space in it, which an unquoted `xargs $SHA256` would split.
( cd "$OUT" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | while IFS= read -r f; do
      # shellcheck disable=SC2086
      $SHA256 "$f"
  done >SHA256SUMS )
ok "SHA256SUMS over $(grep -c . "$OUT/SHA256SUMS") files"

BUNDLE_SZ="$(du -sh "$OUT" | awk '{print $1}')"
ok "bundle: $OUT ($BUNDLE_SZ)"

# ---- optional tarball ------------------------------------------------------------------
# Staged through $TMP and written to $OUT's PARENT: an archive created inside the directory it
# is archiving either self-includes or needs an exclude dance. Archive root is the bundle's
# CONTENTS (./install.sh, ./stubs/, ./bin/), so `tar xzf` lands install.sh where you are.
TARBALL=""
if [ "$MAKE_TAR" -eq 1 ]; then
    HOSTTAG="$(printf '%s-%s' "$HOST_OS" "$HOST_ARCH" | tr '[:upper:]' '[:lower:]')"
    TARBALL="$(cd "$(dirname "$OUT")" && pwd)/sopack-bundle-$ABI-$HOSTTAG-$SOPACK_REV.tar.gz"
    ( cd "$OUT" && tar czf "$TMP/bundle.tar.gz" . )
    mv "$TMP/bundle.tar.gz" "$TARBALL"
    ok "tarball: $TARBALL ($(du -h "$TARBALL" | awk '{print $1}'))"
fi

cat <<EOF

==> Bundle ready. On the target $HOST_OS/$HOST_ARCH machine - no clone, the tool is in the bundle:
EOF
if [ -n "$TARBALL" ]; then
    cat <<EOF

  mkdir -p ~/sopack-bundle && tar xzf $(basename "$TARBALL") -C ~/sopack-bundle
  ~/sopack-bundle/install.sh
  ~/sopack-bundle/venv/bin/sopack pack <your.apk> -o packed.apk --config ~/sopack-bundle/config.yaml
EOF
else
    cat <<EOF

  # copy $(basename "$OUT")/ across, then:
  ./$(basename "$OUT")/install.sh
  ./$(basename "$OUT")/venv/bin/sopack pack <your.apk> -o packed.apk --config ./$(basename "$OUT")/config.yaml
EOF
fi
cat <<EOF

  install.sh installs $WHEEL_NAME into a venv it creates
  beside itself, then verifies the installed sopack can reach its own skeletons. That machine
  needs Python >= 3.9 and network once (pip fetches lief).

  $(basename "$OUT")/README.md lists what else it needs (JDK + apksigner are the ones people
  forget; the sopack repo, the NDK and whitebox-cryptography are NOT needed).
EOF
if [ "$WITH_KEYGEN" -eq 0 ]; then
    cat <<EOF

  This bundle has NO wb_keygen (--allow-foreign-host on a $HOST_OS builder), so its config.yaml
  pins cipher: chacha20. Re-generate it on macOS for wbaes.
EOF
fi
