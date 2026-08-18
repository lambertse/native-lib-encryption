#!/usr/bin/env bash
#
# docker-entrypoint.sh - generate the Linux/x86_64 portable pack bundle inside the builder image.
#
# Thin on purpose. Every gate that matters lives in scripts/artifact_generation.sh and
# scripts/build_wbaes.sh, and duplicating any of them here would give two places to keep in
# step. This does three things the image needs and the scripts should not know about:
#   1. seed the bind-mounted submodule from the deps baked into the image, so a run is offline;
#   2. install sopack into the container's python (the bundler imports it);
#   3. run the bundler into /out, then print the receipts worth reading in CI output.
#
# Arguments are passed straight through to artifact_generation.sh, so:
#   docker run ... sopack-bundler --abi arm64-v8a --api 24 --tar
set -euo pipefail

say()  { printf '\n==> %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

SOPACK=/workspace
# The bundle goes in a SUBDIRECTORY of the mount, not the mount itself, because
# artifact_generation.sh writes its --tar archive BESIDE --out (an archive created inside the
# directory it is archiving would self-include). With --out /out that "beside" is /, i.e. inside
# the container, and the tarball would be lost when it exits.
OUTROOT=/out
OUT="$OUTROOT/bundle"
WBC="$SOPACK/third_party/whitebox-cryptography"

[ -f "$SOPACK/pyproject.toml" ] || die "no sopack checkout bind-mounted at $SOPACK.
       Run with: -v \"\$PWD:/workspace\" -v \"\$PWD/out:/out\""
[ -d "$OUTROOT" ] || die "no output directory bind-mounted at $OUTROOT.
       Run with: -v \"\$PWD/out:/out\"   (so the bundle survives the container)"

# The bundle lands in /out, but the BUILD writes into the mounted checkout: vendor/wbc/,
# sopack/stubs/*.so and the submodule's build-host/ + build-android/. All are gitignored and
# regenerable, so this is safe - except that they are per-host, and replacing a Mac's copies
# with Linux ones means the Mac must re-run build_wbaes.sh before it can pack again. Say so
# when that is about to happen rather than after.
if [ -f "$SOPACK/vendor/wbc/bin/wb_keygen" ] \
   && [ "$(head -c4 "$SOPACK/vendor/wbc/bin/wb_keygen" | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]; then
    printf 'WARN: %s\n' "the mounted checkout carries a NON-ELF vendor/wbc/bin/wb_keygen - it was
      built on macOS. This run replaces it, plus sopack/stubs/*.so and the submodule's
      build-host/, with Linux builds. Nothing is lost that ./scripts/build_wbaes.sh cannot
      rebuild, but that Mac will have to re-run it. Use a separate clone to avoid the churn." >&2
fi

# 1. The submodule. A bind-mounted checkout may have it uninitialised, and the image cannot
#    pre-populate a path that the mount masks - hence the staging copy at /opt/wbc-deps.
say "preparing the whitebox-cryptography submodule"
if [ ! -f "$WBC/include/wbcrypto.h" ]; then
    git -C "$SOPACK" submodule update --init third_party/whitebox-cryptography \
        || die "could not initialise the submodule (needs network unless it is already checked
       out on the host side of the mount)"
fi
# Seed the vendored deps from the image rather than re-downloading them. An existing tree always
# wins: a host that already fetched them, or a dev who deliberately swapped one in, must not be
# overwritten. /opt/wbc-deps is empty when the image could not pre-warm (see the Dockerfile) - in
# that case fall through to fetching, which is the same thing the pre-warm would have done.
mkdir -p "$WBC/third_party"
for d in libsodium omvll python; do
    if [ ! -e "$WBC/third_party/$d" ] && [ -e "/opt/wbc-deps/$d" ]; then
        cp -a "/opt/wbc-deps/$d" "$WBC/third_party/$d"
        printf '    seeded third_party/%s from the image\n' "$d"
    fi
done
# The plugin is only needed for an obfuscated build, so honour the escape hatch: with
# --allow-unobfuscated-provider there is nothing to fetch and nothing to insist on. libsodium is
# needed either way, hence the separate fetch.
WANT_OMVLL=1
for a in "$@"; do
    [ "$a" = "--allow-unobfuscated-provider" ] && WANT_OMVLL=0
done

if [ "$WANT_OMVLL" -eq 1 ] && [ ! -f "$WBC/third_party/omvll/omvll_ndk_r29.so" ]; then
    printf '    no O-MVLL Linux plugin yet - fetching (needs network, once)\n'
    ( cd "$WBC" && ./third_party/fetch_deps.sh all ) \
        || die "fetch_deps.sh failed. If this container has no network, pre-warm the image
       instead (docker build --build-arg WBC_REF=<a pushed sha>), or pass
       --allow-unobfuscated-provider to build without O-MVLL."
    [ -f "$WBC/third_party/omvll/omvll_ndk_r29.so" ] \
        || die "fetch_deps.sh ran but produced no omvll_ndk_r29.so. The submodule predates Linux
       O-MVLL support - update it, or pass --allow-unobfuscated-provider."
elif [ "$WANT_OMVLL" -eq 0 ]; then
    printf '    --allow-unobfuscated-provider: skipping the O-MVLL plugin entirely\n'
    ( cd "$WBC" && ./third_party/fetch_deps.sh libsodium ) || die "fetch_deps.sh libsodium failed"
fi

# 2. sopack itself, into a venv under /tmp rather than the system python.
#    /tmp because this container is meant to run as `--user $(id -u):$(id -g)` so the bundle it
#    writes to /out is not root-owned - and a non-root uid cannot write to
#    /usr/lib/python3/dist-packages. The failure would be a bare permission error naming neither
#    Docker nor sopack.
#    --system-site-packages so lief, pyyaml and pytest come from the image (all three are baked
#    into the Dockerfile's pip layer) instead of being re-fetched; only sopack is installed here.
#    This is why every sopack dependency has to be in that layer: the `pip install -e` below
#    resolves them, so one that is missing sends it to PyPI and an offline run dies right there.
#    Editable, so the bundler reads the mounted checkout - which is the whole point of mounting it.
#    Putting the venv first on PATH is what makes this reach the scripts: build_wbaes.sh and
#    artifact_generation.sh both invoke plain `python3`/`python3 -m pip`.
say "installing sopack (editable) into a venv"
VENV=/tmp/sopack-venv
python3 -m venv --system-site-packages "$VENV" || die "python3 -m venv failed"
export PATH="$VENV/bin:$PATH"
"$VENV/bin/pip" install --quiet --no-cache-dir -e "$SOPACK" \
    || die "pip install -e $SOPACK failed"
python3 -c 'import sopack, lief, yaml' \
    || die "sopack/lief/pyyaml not importable from $VENV after install"

# 3. Generate. --out is under the mount and never $SOPACK/artifacts: artifact_generation.sh does
#    `rm -rf` on its --out, and a checkout mounted from a Mac usually has a working bundle there.
say "generating the bundle"
cd "$SOPACK"
./scripts/artifact_generation.sh --out "$OUT" "$@"

# ---- receipts ----------------------------------------------------------------------------
# The bundler's own gates already passed by here; these are the two facts a reader of the build
# log most wants to confirm at a glance, and both are invisible in a green exit code.
say "receipts"
if [ -f "$OUT/bin/wb_keygen" ]; then
    printf '    wb_keygen: %s\n' "$(file -b "$OUT/bin/wb_keygen")"
    if readelf -d "$OUT/bin/wb_keygen" 2>/dev/null | grep -q NEEDED; then
        die "bin/wb_keygen is dynamically linked - it would carry a glibc floor to the target.
       gate 4 should have caught this; do not ship this bundle."
    fi
    printf '    wb_keygen linkage: static (no DT_NEEDED)\n'
fi
grep -E '^(host-os|host-arch|abi|provider-obfuscation|wb-keygen-linkage|wbc-rev)' \
    "$OUT/MANIFEST.txt" | sed 's/^/    /'

cat <<EOF

==> Done. On the host: the bundle is ./out/bundle/, and --tar puts the archive beside it in
    ./out/. To use it on the target machine:

      mkdir -p ~/sopack-bundle
      tar xzf out/sopack-bundle-*.tar.gz -C ~/sopack-bundle   # if you passed --tar
      ~/sopack-bundle/install.sh
      ~/sopack-bundle/venv/bin/sopack pack <your.apk> -o packed.apk

    That machine needs python3 (>= 3.9) WITH venv, a JDK, apksigner, and network once for pip
    to fetch lief. See the bundle's README.md.
EOF
