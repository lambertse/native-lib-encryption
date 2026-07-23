# syntax=docker/dockerfile:1
#
# sopack — reproducible build + pack environment.
# ---------------------------------------------------------------------------------------
# Reproduces this project's toolchain so that packing an APK (including the O-MVLL
# obfuscated / polymorphic stub path) needs nothing installed on the host but Docker.
#
# WHY x86_64 emulation:
#   The Android NDK ships host binaries ONLY for linux-x86_64, and the O-MVLL obfuscator
#   plugin is published only for x86_64/macOS. On an Apple-Silicon (arm64) Mac these run
#   under Docker Desktop's Rosetta. Enable it once:
#     Docker Desktop > Settings > General > "Use Rosetta for x86/amd64 emulation".
#   This image is arm64-native (fast sopack/LIEF/Java) and installs the amd64 runtime libs
#   so Rosetta can execute the x86_64-only NDK clang + O-MVLL when --obfuscate is used.
#   On an x86_64 host everything is native and no Rosetta is involved.
#
# BUILD (from the repo root, which is the build context):
#     docker build -f assets/Dockerfile/Dockerfile -t sopack .
#
# PACK an APK (mount a working dir with your input APK):
#     docker run --rm -v "$PWD:/work" -w /work sopack \
#         pack in.apk --lib libfoo.so -o out.apk
#   Obfuscated + per-pack polymorphic stub (uses the emulated NDK + O-MVLL):
#     docker run --rm -v "$PWD:/work" -w /work sopack \
#         pack in.apk --lib libfoo.so -o out.apk --obfuscate
#
# UPDATING: bump the ARGs below when the host toolchain changes, and keep this file in
#   sync with the machine (see assets/Dockerfile/README.md).
# ---------------------------------------------------------------------------------------

FROM debian:12-slim

# --- pinned external toolchain versions (bump together; NDK and O-MVLL MUST match) ------
# O-MVLL 1.6.0 (needs only GLIBC_2.35) is chosen so the x86_64 plugin runs on this Debian 12
# (glibc 2.36) base under Rosetta. Newer O-MVLL (1.8.0+) needs GLIBC_2.38 and would require a
# newer base (e.g. ubuntu:24.04) + matching NDK. Keep NDK and O-MVLL compatible (see README).
ARG NDK_VERSION=r26d
ARG OMVLL_VERSION=1.6.0
ARG OMVLL_ASSET=omvll_v1-6-0_linux_2026-04-23T13_47_22.tar.gz
ARG STUB_API_LEVEL=24

ENV DEBIAN_FRONTEND=noninteractive

# --- base toolchain (arm64-native): clang/lld/llvm for the default stub build + the
#     build guards, python+LIEF for sopack, JDK + apksigner for signing, fetch/zip utils.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang lld llvm \
        python3 python3-pip \
        openjdk-17-jdk-headless apksigner \
        git make curl ca-certificates unzip zip xz-utils \
    && rm -rf /var/lib/apt/lists/*

# --- amd64 runtime libs so Rosetta/qemu can execute the x86_64-only NDK clang + O-MVLL.
#     (clang/lld NEEDED: libc, libgcc_s, libz, libxml2; O-MVLL NEEDED: libc, libm, libz.)
RUN dpkg --add-architecture amd64 && apt-get update && apt-get install -y --no-install-recommends \
        libc6:amd64 libgcc-s1:amd64 libstdc++6:amd64 zlib1g:amd64 libxml2:amd64 \
    && rm -rf /var/lib/apt/lists/*

# --- Android NDK (x86_64 host binaries; executed via Rosetta on arm64) ------------------
RUN curl -fsSL -o /tmp/ndk.zip \
        "https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip" \
    && unzip -q /tmp/ndk.zip -d /opt && rm /tmp/ndk.zip
ENV ANDROID_NDK_HOME=/opt/android-ndk-${NDK_VERSION}
ENV ANDROID_NDK_ROOT=/opt/android-ndk-${NDK_VERSION}

# --- O-MVLL obfuscator plugin (built against this NDK's LLVM) + its bundled Python stdlib.
RUN mkdir -p /opt/omvll \
    && curl -fsSL -o /tmp/omvll.tgz \
        "https://github.com/open-obfuscator/o-mvll/releases/download/${OMVLL_VERSION}/${OMVLL_ASSET}" \
    && tar -xzf /tmp/omvll.tgz -C /opt/omvll && rm /tmp/omvll.tgz
ENV OMVLL_PLUGIN=/opt/omvll/omvll-ndk.so
ENV OMVLL_PYTHONPATH=/opt/omvll/Python-3.10.7/Lib

# --- sopack itself (source baked in; APKs are mounted at runtime) -----------------------
WORKDIR /opt/sopack
COPY pyproject.toml README.md ./
COPY sopack/ ./sopack/
COPY stub/ ./stub/
COPY tests/ ./tests/
COPY docs/ ./docs/
RUN pip3 install --no-cache-dir --break-system-packages -e . \
    # Prebuild the default (non-obfuscated) per-ABI stub blobs with the native arm64 clang.
    # ANDROID_NDK_HOME is unset for THIS command only so build_stubs.sh picks the native
    # clang (the x86_64 NDK clang can't run during `docker build` without Rosetta). The
    # obfuscated stubs are (re)built per pack at runtime via --obfuscate (Rosetta path).
    && env -u ANDROID_NDK_HOME -u ANDROID_NDK_ROOT bash stub/build_stubs.sh ${STUB_API_LEVEL}

WORKDIR /work
ENTRYPOINT ["sopack"]
CMD ["--help"]
