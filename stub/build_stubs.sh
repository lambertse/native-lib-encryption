#!/usr/bin/env bash
#
# build_stubs.sh — compile the injectable decryption stub into flat, relocation-free
# blobs (one per ABI) plus a JSON sidecar recording the offsets the injector needs
# (sopk_entry and g_decinfo within the blob).
#
# The stub is freestanding (raw syscalls, no Android sysroot), so it can be built with
# EITHER the Android NDK or a plain multi-target LLVM. Toolchain selection:
#   * ANDROID_NDK_HOME / ANDROID_NDK_ROOT set  -> use the NDK's clang/llvm.
#   * otherwise                                -> use clang / llvm-objcopy / llvm-readelf
#                                                 from PATH (e.g. conda-forge LLVM).
# Output goes to sopack/stubs/ so the Python package can ship the blobs as data.
#
# Usage: ANDROID_NDK_HOME=/path/to/ndk ./build_stubs.sh [API_LEVEL]
#    or: ./build_stubs.sh            # plain LLVM on PATH
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../sopack/stubs"
API="${1:-24}"
mkdir -p "$OUT"

# ABI -> clang target triple
declare -A TARGET=(
    [arm64-v8a]="aarch64-linux-android${API}"
    [armeabi-v7a]="armv7a-linux-androideabi${API}"
    [x86_64]="x86_64-linux-android${API}"
)

NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
if [[ -n "$NDK" ]]; then
    HOSTTAG="$(uname | tr '[:upper:]' '[:lower:]')-x86_64"
    BIN="$NDK/toolchains/llvm/prebuilt/$HOSTTAG/bin"
    CLANG="$BIN/clang"
    OBJCOPY="$BIN/llvm-objcopy"
    READELF="$BIN/llvm-readelf"
    echo "toolchain: NDK ($NDK)"
else
    CLANG="$(command -v clang)"
    OBJCOPY="$(command -v llvm-objcopy)"
    READELF="$(command -v llvm-readelf)"
    if [[ -z "$CLANG" || -z "$OBJCOPY" || -z "$READELF" ]]; then
        echo "ERROR: need either ANDROID_NDK_HOME or clang+llvm-objcopy+llvm-readelf on PATH" >&2
        exit 1
    fi
    echo "toolchain: plain LLVM ($CLANG)"
fi

CFLAGS=(
    -Os -fPIC -fno-plt -ffreestanding -nostdlib
    -fvisibility=hidden -fno-stack-protector -fno-jump-tables
    -fno-asynchronous-unwind-tables -fno-unwind-tables
    -fno-builtin -fomit-frame-pointer -std=c11 -Wall -Wextra
)
LDFLAGS=(
    -nostdlib -static -fuse-ld=lld -Wl,--build-id=none -Wl,-e,sopk_entry
    -Wl,--no-dynamic-linker -Wl,--gc-sections
    -Wl,-T,"$HERE/stub.ld"
)

sym_off() {  # sym_off <elf> <name> -> hex offset (== vaddr, image based at 0)
    "$READELF" -sW "$1" | awk -v n="$2" '$8==n {print "0x"$2; exit}'
}

for ABI in "${!TARGET[@]}"; do
    TRIPLE="${TARGET[$ABI]}"
    echo "== building stub for $ABI ($TRIPLE) =="
    ELF="$OUT/stub_${ABI}.elf"
    BLOB="$OUT/stub_${ABI}.bin"
    META="$OUT/stub_${ABI}.json"

    "$CLANG" --target="$TRIPLE" "${CFLAGS[@]}" "${LDFLAGS[@]}" \
        -I"$HERE" "$HERE/stub.c" -o "$ELF"

    # Hard requirement: no dynamic relocations and no undefined symbols, or the blob
    # is not self-contained and will crash when injected.
    if "$READELF" -rW "$ELF" | grep -qiE 'R_(AARCH64|ARM|X86_64)_'; then
        echo "ERROR: $ABI stub has relocations (not position-independent enough):" >&2
        "$READELF" -rW "$ELF" >&2
        exit 1
    fi
    if "$READELF" -sW "$ELF" | awk '$7=="UND" && $8!="" {found=1} END{exit !found}'; then
        echo "ERROR: $ABI stub references undefined (external) symbols:" >&2
        "$READELF" -sW "$ELF" | awk '$7=="UND" && $8!=""' >&2
        exit 1
    fi

    ENTRY_OFF="$(sym_off "$ELF" sopk_entry)"
    INFO_OFF="$(sym_off "$ELF" g_decinfo)"
    [[ -n "$ENTRY_OFF" && -n "$INFO_OFF" ]] || { echo "ERROR: missing symbols in $ABI" >&2; exit 1; }

    "$OBJCOPY" -O binary "$ELF" "$BLOB"
    SIZE="$(wc -c < "$BLOB")"

    cat > "$META" <<EOF
{
  "abi": "$ABI",
  "triple": "$TRIPLE",
  "api": $API,
  "size": $SIZE,
  "entry_off": $((ENTRY_OFF)),
  "decinfo_off": $((INFO_OFF))
}
EOF
    echo "   -> $BLOB ($SIZE bytes)  entry=+$((ENTRY_OFF))  decinfo=+$((INFO_OFF))"
    rm -f "$ELF"
done

echo "All stubs built into $OUT"
