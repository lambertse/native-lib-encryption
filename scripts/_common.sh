#!/usr/bin/env bash
#
# _common.sh - shared preflight / prompt / reporting helpers for scripts/build_<cipher>.sh.
# Sourced, never executed on its own.
#
# Bash 3.2 compatible on purpose: macOS still ships /bin/bash 3.2, and that is the primary
# pack host for this project. So no associative arrays, no `mapfile`, no `${var,,}`, and
# indirect assignment via `eval` rather than a nameref. Same conventions as
# stub/build_stubs.sh (`set -euo pipefail` in the caller, `ERROR: … >&2`).

say()  { printf '==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    OK: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# step N TOTAL "title"
step() { printf '\n==> [%s/%s] %s\n' "$1" "$2" "$3"; }

have() { command -v "$1" >/dev/null 2>&1; }

# need TOOL ["why it is needed"]
need() {
    have "$1" || die "missing required tool: $1${2:+ - $2}"
}

# ask_path VAR "prompt" VALIDATOR ["hint on failure"]
#
# Resolves VAR from its current value (env or a --flag the caller already assigned), else by
# prompting. VALIDATOR is a function name invoked with the candidate path; it must explain the
# problem on stderr and return non-zero when the path is unusable.
#
# Deliberately dies rather than prompting when stdin is not a terminal - a build script that
# blocks forever waiting on a read is worse than one that fails with a usage message.
ask_path() {
    local var="$1" prompt="$2" validator="$3" hint="${4:-}"
    local cur
    eval "cur=\${$var:-}"
    while :; do
        if [ -n "$cur" ]; then
            case "$cur" in "~/"*) cur="$HOME/${cur#\~/}" ;; esac
            cur="${cur%/}"
            if "$validator" "$cur"; then
                eval "$var=\$cur"
                return 0
            fi
            # Came from env/flag and is wrong: never silently re-prompt in a pipeline.
            [ -t 0 ] || die "$var=$cur is not usable (see above).${hint:+ $hint}"
            cur=""
        fi
        [ -t 0 ] || die "$var is not set and stdin is not a terminal.${hint:+ $hint}"
        printf '%s' "$prompt"
        read -r cur || die "$var not provided"
    done
}

# ---- host-binary portability -------------------------------------------------------------
# elf_needed FILE - print this ELF's DT_NEEDED sonames, one per line; nothing when it is
# statically linked. Used on Linux by build_wbaes.sh (to decide a cached wb_keygen is stale)
# and by artifact_generation.sh gate 4 (to refuse bundling a non-portable one). One definition
# because those two must agree on what "static" means, or the build produces a keygen the
# bundler then rejects.
#
# Exit status 2 means "could not tell" (no readelf/objdump), which is NOT the same as "static"
# and callers must not conflate them - silently treating unknown as static is how a
# glibc-floored binary would reach the target machine.
elf_needed() {
    if have readelf; then
        readelf -d "$1" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p'
    elif have objdump; then
        objdump -p "$1" 2>/dev/null | awk '$1 == "NEEDED" { print $2 }'
    else
        return 2
    fi
}

# elf_machine FILE - print the ELF e_machine number (62 = x86-64, 183 = AArch64), or nothing if
# FILE is not a little-endian ELF. Read straight out of the header rather than parsed from
# `readelf -h`, whose wording varies between binutils and LLVM ("Advanced Micro Devices X86-64"
# vs "X86-64"); the number is the stable thing.
elf_machine() {
    [ "$(od -An -tx1 -j0 -N4 "$1" 2>/dev/null | tr -d ' \n')" = "7f454c46" ] || return 0
    # EI_DATA (byte 5): 1 = little-endian. od interprets multi-byte values host-endian, so bail
    # rather than misreport on a big-endian object. Nothing sopack targets is big-endian.
    [ "$(od -An -tu1 -j5 -N1 "$1" 2>/dev/null | tr -d ' \n')" = "1" ] || return 0
    od -An -tu2 -j18 -N2 "$1" 2>/dev/null | tr -d ' \n'
}

# host_elf_machine - the e_machine this host runs natively, or nothing if we cannot say.
#
# This exists because "the binary executed, so it is the right architecture" IS NOT TRUE, and the
# way it fails is silent. Docker Desktop on Apple Silicon runs a linux/amd64 container on an
# aarch64 kernel, so an aarch64 ELF inside that container runs perfectly while `uname -m` reports
# x86_64. A wb_keygen built in that state seals blobs happily on the builder and is a dead file on
# the actual x86_64 target - after every gate has gone green.
host_elf_machine() {
    case "$(uname -m)" in
        x86_64|amd64)   echo 62 ;;
        aarch64|arm64)  echo 183 ;;
        armv7l|armv6l)  echo 40 ;;
        i386|i686)      echo 3 ;;
        riscv64)        echo 243 ;;
        ppc64le)        echo 21 ;;
        s390x)          echo 22 ;;
    esac
}

# elf_machine_name NUM - a human name for the numbers above, for error messages.
elf_machine_name() {
    case "$1" in
        62)  echo "x86-64" ;;   183) echo "AArch64" ;;  40) echo "ARM" ;;
        3)   echo "i386" ;;     243) echo "RISC-V" ;;   21) echo "ppc64le" ;;
        22)  echo "s390x" ;;    "")  echo "not an ELF" ;;
        *)   echo "EM_$1" ;;
    esac
}

# ---- the whitebox-cryptography dependency ------------------------------------------------
# WBC is a PINNED GIT SUBMODULE at third_party/whitebox-cryptography. It used to arrive out of
# band, which meant three scripts each guessed a different default and none of them recorded
# which revision built the artifacts. One resolver, one precedence list, one place to change.

WBC_SUBMODULE="third_party/whitebox-cryptography"

# resolve_wbc SOPACK [--no-prompt]
#
# Sets WBC. Precedence, highest first:
#   1. $WBC          - already assigned by a --wbc flag or exported by the user
#   2. the submodule - $SOPACK/third_party/whitebox-cryptography, initialised on demand
#   3. the sibling   - $SOPACK/../whitebox-cryptography, the pre-submodule dev layout
#   4. a prompt      - unless --no-prompt (artifact_generation.sh runs unattended)
#
# 2 sits ahead of 3 so a clean clone works with no arguments; 3 survives so an existing
# side-by-side checkout keeps working. The caller still runs valid_wbc afterwards: this decides
# WHICH tree, not whether that tree is usable.
resolve_wbc() {
    local sopack="$1" no_prompt="${2:-}"
    local sub="$sopack/$WBC_SUBMODULE"

    if [ -z "${WBC:-}" ]; then
        # An UNINITIALISED submodule is an empty directory, so `-d` is not a usable test here -
        # it passes, and the failure surfaces much later as "not a whitebox-cryptography
        # checkout". Test for the header, and initialise when it is missing.
        if [ ! -f "$sub/include/wbcrypto.h" ] && [ -f "$sopack/.gitmodules" ]; then
            say "initialising the whitebox-cryptography submodule (pinned)"
            # No --recursive: WBC has no nested submodules. Its own third_party/ (libsodium,
            # O-MVLL) is a SHA256-pinned tarball fetch that its build scripts run themselves.
            ( cd "$sopack" && git submodule update --init "$WBC_SUBMODULE" ) \
                || die "git submodule update --init $WBC_SUBMODULE failed. It needs network the
       first time. To use a checkout you already have, pass --wbc PATH or export WBC."
        fi
        if [ -f "$sub/include/wbcrypto.h" ]; then
            WBC="$sub"
        elif [ -f "$sopack/../whitebox-cryptography/include/wbcrypto.h" ]; then
            WBC="$(cd "$sopack/../whitebox-cryptography" && pwd)"
            info "using the sibling checkout $WBC (the submodule at $WBC_SUBMODULE is empty)"
        fi
    fi

    if [ "$no_prompt" = "--no-prompt" ]; then
        [ -n "${WBC:-}" ] || die "no whitebox-cryptography checkout. Expected the submodule at
       $sub - run: git submodule update --init $WBC_SUBMODULE
       (or pass --wbc PATH / export WBC). This script never prompts."
        valid_wbc "$WBC" || die "WBC=$WBC is not usable (see above)."
        return 0
    fi
    ask_path WBC "whitebox-cryptography checkout (>= 3.0.0): " valid_wbc \
        "Pass --wbc PATH, export WBC, or run: git submodule update --init $WBC_SUBMODULE"
}

# valid_wbc PATH - the >= 3.0.0 gate, shared so the three callers cannot drift.
valid_wbc() {
    [ -d "$1" ] || { warn "$1 is not a directory"; return 1; }
    [ -f "$1/include/wbcrypto.h" ] || {
        warn "$1 has no include/wbcrypto.h - that is not a whitebox-cryptography checkout"
        warn "(an UNINITIALISED submodule looks exactly like this: git submodule update --init)"
        return 1; }
    # gen_blob.sh, NOT build_host.sh. Both exist upstream and they are different tools:
    # build_host.sh builds the tests and tools into build/ and honours ZIG_BIN/EXTRA_CXXFLAGS,
    # while gen_blob.sh deliberately REFUSES both so no cross toolchain or O-MVLL plugin can
    # leak into a provisioning tool, and writes build-host/wb_keygen. Upstream calls that path
    # "part of the consumer contract" with this repo by name. Do not "modernise" this to
    # build_host.sh - it would hand us an obfuscated or cross-built keygen that cannot run here.
    [ -f "$1/scripts/gen_blob.sh" ] || {
        warn "$1 has no scripts/gen_blob.sh - too old, or not the right repo"; return 1; }
    # The version gate that matters. 3.0.0 made the seal's KDF cost a per-blob tier and added
    # wbc_blob_kdf_tier; sopack seals at `light` and the helper ctor reads the tier back, so a
    # pre-3.0.0 header will not compile and a pre-3.0.0 archive fails at link.
    grep -q 'wbc_blob_kdf_tier' "$1/include/wbcrypto.h" || {
        warn "$1/include/wbcrypto.h does not declare wbc_blob_kdf_tier, so this checkout is"
        warn "pre-3.0.0. sopack requires >= 3.0.0 (the light KDF tier); update it and retry."
        grep -q 'wbc_unwrap_key' "$1/include/wbcrypto.h" \
            || warn "(it does not even have wbc_unwrap_key, so it is pre-2.0.0)"
        return 1; }
    return 0
}
