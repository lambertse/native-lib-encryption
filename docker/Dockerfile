# syntax=docker/dockerfile:1
# check=skip=FromPlatformFlagConstDisallowed
#
# The skip is deliberate. BuildKit's lint prefers `docker build --platform` over a constant on
# FROM, on the reasoning that the base should follow the requested platform. Here it must not:
# this image is x86_64-only by hard dependency (no linux-aarch64 NDK toolchain, and O-MVLL
# publishes no aarch64 Linux plugin), so pinning it means someone who forgets the build flag on
# an Apple Silicon Mac gets a slow-but-correct image instead of an arm64 one that fails later.
#
# A Linux/x86_64 builder for the portable pack bundle (scripts/artifact_generation.sh).
#
# Why this exists: the bundle carries one host-specific file, bin/wb_keygen, so a bundle that
# installs on a Linux x86_64 machine has to be GENERATED on one. Everything else it needs - the
# stub blobs, both wbaes skeletons, the wheel - is host-neutral.
#
# --platform=linux/amd64 is NOT a preference. Google publishes no linux-aarch64 NDK toolchain
# (build_wbaes.sh checks and says so), and O-MVLL ships its Linux plugin for x86_64 only. Both
# hard-fail on an arm64 image. Build this on a native amd64 host: an emulated build dlopens a
# 64 MB x86_64 LLVM pass-plugin with an embedded CPython into an x86_64 clang under qemu-user,
# which is where an emulated build is most likely to diverge from a native one - see README.md.
#
# ubuntu:24.04 (glibc 2.39) and NOT debian:bookworm (2.36), for one reason: the O-MVLL 1.9.1
# Linux plugin requires GLIBC_2.38. On bookworm clang refuses it with
#   error: unable to load plugin '...omvll_ndk_r29.so': ... libm.so.6: version `GLIBC_2.38' not
#   found
# repeated once per translation unit. The floor is asserted below so a future base change cannot
# reintroduce that quietly.
#
# This says nothing about where the BUNDLE can run. Its one native binary, bin/wb_keygen, is
# linked statically precisely so the builder's glibc never becomes the target's problem.
FROM --platform=linux/amd64 ubuntu:24.04

# One layer, no recommends, and the apt lists dropped afterwards: this image is big enough
# already (the NDK is ~2.5 GB unpacked).
#
#   build-essential/g++   the host C++ compiler gen_blob.sh picks up for wb_keygen. It also
#                         supplies libstdc++.a and libc.a, which the STATIC link of wb_keygen
#                         needs; the assertion below proves that rather than trusting a package
#                         name, since the right libstdc++-N-dev tracks the base's default gcc.
#   cmake + ninja-build   WBC's scripts/build_android.sh configures with -GNinja
#   python3-venv          NOT optional. The bundle's install.sh creates a venv, and Debian/Ubuntu
#                         python3 has no ensurepip without it; the failure names the package but
#                         only after everything else has succeeded. Present here so the image can
#                         smoke-test its own bundle.
#   openjdk-17-jdk-headless  keytool, which sopack runs on the first pack even without
#                         --keystore, plus the JVM apksigner needs
#   apksigner             signs the packed APK. Not needed to BUILD a bundle, but this image is
#                         also where packing gets smoke-tested, and without it a pack ends in
#                         "could not find apksigner" after all the real work succeeded. Ubuntu
#                         ships it standalone, so no Android SDK is required.
#   zlib1g                the O-MVLL plugin links libz
#   file, binutils        `file -b` describes wb_keygen in MANIFEST.txt; readelf backs gate 4
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential g++ clang lld \
        cmake ninja-build \
        python3 python3-pip python3-venv python3-dev \
        git curl ca-certificates tar unzip xz-utils file binutils \
        openjdk-17-jdk-headless apksigner zlib1g openssl \
    && rm -rf /var/lib/apt/lists/*

# Two capability assertions, both build-time so a base-image change cannot break them silently.
# Each replaces a guess ("bookworm has a new enough glibc", "libstdc++-12-dev is the right
# package name") with a proof.
#
#   1. glibc >= 2.38, or the O-MVLL plugin will not load into clang - see the FROM comment.
#   2. `-static -static-libstdc++ -static-libgcc` actually links and the result has no
#      DT_NEEDED. This is the property the whole bundle rests on: gate 4 of
#      artifact_generation.sh refuses a dynamically linked wb_keygen, so if this cannot work the
#      image is useless and should say so now rather than 20 minutes into a build.
RUN set -eu; \
    glibc="$(ldd --version | head -1 | grep -oE '[0-9]+\.[0-9]+$')"; \
    echo "glibc: $glibc"; \
    if [ "$(printf '2.38\n%s\n' "$glibc" | sort -V | head -1)" != "2.38" ]; then \
        echo "ERROR: glibc $glibc < 2.38; the O-MVLL 1.9.1 Linux plugin requires GLIBC_2.38" >&2; \
        echo "       and clang would refuse to load it, once per translation unit." >&2; \
        exit 1; \
    fi; \
    printf '#include <string>\n#include <cstdio>\nint main(){std::string s="ok";puts(s.c_str());}\n' \
        > /tmp/t.cpp; \
    c++ /tmp/t.cpp -static -static-libstdc++ -static-libgcc -o /tmp/t \
        || { echo "ERROR: static libstdc++/libc link unavailable in this base image." >&2; exit 1; }; \
    /tmp/t; \
    if readelf -d /tmp/t | grep -q NEEDED; then \
        echo "ERROR: -static produced a binary with DT_NEEDED entries" >&2; exit 1; \
    fi; \
    echo "static C++ link: OK (no DT_NEEDED)"; \
    rm -f /tmp/t /tmp/t.cpp

# Installed system-wide so the entrypoint's venv can inherit them via --system-site-packages and
# the container never has to reach PyPI at run time.
#   pytest       a hard requirement, not a convenience: build_wbaes.sh Phase 2 runs the suite and
#                dies on failure, so without it `Host phases 1-4 PASS` never prints and
#                artifact_generation.sh refuses to bundle.
#   lief         what sopack does all its ELF surgery with.
#   pyyaml       sopack's config file parser. Every setting except the input and output APK
#                lives in config.yaml, so this is as hard a runtime requirement as lief - and
#                it must be HERE, not left to pip: the entrypoint runs `pip install -e` inside
#                a --system-site-packages venv, so a dependency missing from this layer sends
#                that install to PyPI and an offline run dies there. Keep in step with
#                pyproject.toml's `dependencies`.
#   setuptools   the build backend for `pip install -e` and for the bundle's own wheel. Present
#                explicitly because artifact_generation.sh tries an ISOLATED wheel build first,
#                which would otherwise want to download it.
RUN pip3 install --no-cache-dir --break-system-packages \
        pytest 'lief>=1.0' 'pyyaml>=6' 'setuptools>=68' wheel

# ---- Android NDK r29 --------------------------------------------------------------------
# Pinned to 29.0.14206865, which Google's own repository2-3.xml maps to android-ndk-r29-linux.zip.
# The version is dictated by O-MVLL: its plugin is built against r29's clang (WBC installs it as
# omvll_ndk_r29.so) and an LLVM pass-plugin only loads into the compiler it was built for. Do not
# "upgrade" this without also moving the O-MVLL pin in the whitebox-cryptography submodule.
#
# SHA1 rather than SHA256 because that is the checksum Google publishes in the manifest; the
# integrity that matters downstream is the bundle's own SHA256SUMS.
ARG NDK_ZIP=android-ndk-r29-linux.zip
ARG NDK_SHA1=87e2bb7e9be5d6a1c6cdf5ec40dd4e0c6d07c30b
RUN curl -fsSL -o /tmp/ndk.zip "https://dl.google.com/android/repository/${NDK_ZIP}" \
    && echo "${NDK_SHA1}  /tmp/ndk.zip" | sha1sum -c - \
    && unzip -q /tmp/ndk.zip -d /opt \
    && rm /tmp/ndk.zip \
    && test -d /opt/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin
ENV NDK=/opt/android-ndk-r29
ENV ANDROID_NDK_HOME=/opt/android-ndk-r29

# ---- pre-warm the whitebox-cryptography dependencies -------------------------------------
# WBC's fetch_deps.sh downloads libsodium, the O-MVLL Linux plugin and a CPython 3.10 stdlib
# (~150 MB) on first build. Baking them in means each container run is offline and repeatable,
# and it makes the download failures build-time rather than run-time.
#
# Fetched into a THROWAWAY clone and then copied to a staging path, because the real submodule
# arrives as a bind mount at run time and anything written here would be masked by it.
# docker-entrypoint.sh seeds the mounted submodule from this staging copy.
#
# This layer is an OPTIMISATION and is deliberately BEST-EFFORT. It needs WBC_REF to exist on the
# REMOTE, and while Linux O-MVLL support is new that ref may still be only on someone's laptop -
# which must not make the image unbuildable, because the mounted checkout at run time already has
# everything needed. So: pre-warm when we can, and leave a note when we cannot.
# docker-entrypoint.sh checks /opt/wbc-deps and falls back to fetching into the mounted submodule
# (which costs ~150 MB of network on the first run, and nothing after).
#
# Prefer passing a SHA (--build-arg WBC_REF=<sha>) matching the submodule pin once it is pushed:
# a branch name resolves to whatever its tip is at build time, which can drift from the checkout.
ARG WBC_REPO=https://github.com/lambertse/whitebox-cryptography
ARG WBC_REF=feat/linux-omvll
SHELL ["/bin/bash", "-eu", "-o", "pipefail", "-c"]
RUN mkdir -p /opt/wbc-deps; \
    prewarm() { \
        git clone --quiet "$WBC_REPO" /tmp/wbc || return 1; \
        git -C /tmp/wbc checkout --quiet "$WBC_REF" || return 1; \
        grep -q 'omvll_plugin_path' /tmp/wbc/third_party/fetch_deps.sh || return 1; \
        ( cd /tmp/wbc && ./third_party/fetch_deps.sh all ) || return 1; \
        cp -a /tmp/wbc/third_party/libsodium /tmp/wbc/third_party/omvll \
              /tmp/wbc/third_party/python /opt/wbc-deps/ || return 1; \
        test -f /opt/wbc-deps/omvll/omvll_ndk_r29.so || return 1; \
        test -f /opt/wbc-deps/python/Lib/abc.py || return 1; \
    }; \
    if prewarm; then \
        echo "pre-warmed the whitebox-cryptography deps from $WBC_REF"; \
    else \
        rm -rf /opt/wbc-deps; mkdir -p /opt/wbc-deps; \
        echo "NOTE: could not pre-warm from '$WBC_REF' in $WBC_REPO - either the ref is not on"; \
        echo "      the remote yet, or it predates Linux O-MVLL support. The image is still"; \
        echo "      usable: the entrypoint will fetch the deps into the mounted submodule on"; \
        echo "      the first run, which needs network once. Rebuild with --build-arg WBC_REF=<sha>"; \
        echo "      once the commit is pushed to bake them in."; \
    fi; \
    rm -rf /tmp/wbc

WORKDIR /workspace
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--tar"]
