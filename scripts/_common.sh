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
