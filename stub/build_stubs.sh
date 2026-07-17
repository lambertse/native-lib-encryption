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
#
# Requires an NDK r19+ (recommend r26-r28; must bundle lld — a real version looks like
# 27.0.12077973, NOT 4.8.0) OR a modern LLVM (clang + lld + llvm-objcopy + llvm-readelf)
# on PATH. Run with bash (>= 3.2), not sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../sopack/stubs"
API="${1:-24}"
mkdir -p "$OUT"

# ABI:triple pairs. Kept as a plain space-separated list (not a bash-4 associative
# array) so this script also runs on macOS's built-in bash 3.2.
TARGETS="arm64-v8a:aarch64-linux-android${API} \
armeabi-v7a:armv7a-linux-androideabi${API} \
x86_64:x86_64-linux-android${API}"

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

for PAIR in $TARGETS; do
    ABI="${PAIR%%:*}"
    TRIPLE="${PAIR#*:}"
    echo "== building stub for $ABI ($TRIPLE) =="
    ELF="$OUT/stub_${ABI}.elf"
    BLOB="$OUT/stub_${ABI}.bin"
    META="$OUT/stub_${ABI}.json"

    # arm64: force -mcmodel=tiny so the compiler emits `adr` (byte PC-relative) instead
    # of `adrp+add` (page PC-relative). `adrp` is only correct when the blob loads at a
    # page-aligned virtual address; some LIEF versions place the injected segment at a
    # non-page-aligned vaddr, which breaks `adrp` addressing to g_decinfo. `adr` works at
    # any alignment. (x86_64 RIP-relative and armv7 literal pools are already byte-relative.)
    EXTRA=""
    if [ "$ABI" = "arm64-v8a" ]; then EXTRA="-mcmodel=tiny"; fi

    "$CLANG" --target="$TRIPLE" $EXTRA "${CFLAGS[@]}" "${LDFLAGS[@]}" \
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
    # arm64: the blob MUST use adr (byte PC-relative), never adrp (page PC-relative),
    # or it breaks when a LIEF version places the injected segment at a non-page-aligned
    # virtual address. -mcmodel=tiny guarantees adr; assert it here.
    if [ "$ABI" = "arm64-v8a" ]; then
        OBJDUMP="$(dirname "$READELF")/llvm-objdump"
        if "$OBJDUMP" -d "$ELF" | grep -qw adrp; then
            echo "ERROR: $ABI stub uses adrp (page-relative) — must build with -mcmodel=tiny" >&2
            exit 1
        fi
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
