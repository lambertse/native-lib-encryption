#!/usr/bin/env bash
#
# Example: pack an APK with sopack, encrypting a native library and shipping a per-pack-unique,
# O-MVLL-obfuscated (polymorphic) decryption stub. Copy and edit this for your own APK.
#
# Run it from the repository root:
#     bash examples/build-obfuscated-apk.sh
#
# Preferred (portable) way to get the obfuscation toolchain is the Docker image; see
# assets/Dockerfile/README.md. This script targets the local dev container where the NDK +
# O-MVLL live under $HOME.
set -euo pipefail

# ---- inputs (edit these) -------------------------------------------------------------------
INPUT_APK="assets/app-release.apk"                 # the APK to protect
LIBS="libapp.so"                                   # comma-separated .so names to encrypt
ABI="arm64-v8a"                                    # NOTE: --obfuscate applies to arm64-v8a only
OUTPUT_APK="output/app-release-encrypted.apk"      # where to write the result

# ---- obfuscation toolchain (O-MVLL + Android NDK) ------------------------------------------
# These three env vars are what --obfuscate needs. Inside the sopack Docker image they are
# already set; in this dev container they point at the installed toolchain under $HOME.
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/android-ndk-r26d}"
export OMVLL_PLUGIN="${OMVLL_PLUGIN:-$HOME/omvll16/omvll-ndk.so}"
export OMVLL_PYTHONPATH="${OMVLL_PYTHONPATH:-$HOME/omvll16/Python-3.10.7/Lib}"

mkdir -p "$(dirname "$OUTPUT_APK")"

# ---- pack ----------------------------------------------------------------------------------
#   --obfuscate : recompile a per-pack-unique, O-MVLL-obfuscated arm64 stub (polymorphism)
#   --log       : stub emits a logcat line (tag 'sopack') on successful decrypt — drop it for
#                 a silent stub in a release build
#   --verify    : print the signing certificate after signing
python3 -m sopack.cli pack "$INPUT_APK" \
    --lib "$LIBS" \
    --abi "$ABI" \
    -o "$OUTPUT_APK" \
    --obfuscate \
    --log \
    --verify

echo
echo "Built: $OUTPUT_APK"
