"""sopack's process exit codes - the machine-readable half of a pack result.

`sopack pack` used to collapse every failure into 1, so a caller could tell "it broke" but not
what broke, and had to scrape stdout for anything else. These codes give each failure class a
stable number; the *counts* (how many libraries were encrypted) deliberately do NOT live here -
they live in the run record (`sopack/report.py`), for reasons worth writing down because the
obvious design does not work:

* **A process exit status is 8 bits, unsigned.** The console script is `sopack.cli:main`
  (pyproject.toml), which setuptools wraps as `sys.exit(main())`, and CPython masks the value -
  `sys.exit(-1)` is observed by the shell as 255 and `-2` as 254. Negative codes are not
  representable, so "-1 for this error, -2 for that one" cannot survive the process boundary.
* **One byte cannot carry a class AND a count.** Returning the number of encrypted libraries
  would collide with every error code in the same range: exit 3 would mean both "config error"
  and "3 libraries encrypted".
* **0 must keep meaning success.** `set -e`, CI runners and `make` all read 0 that way, so
  giving 0 to "nothing was encrypted" would guarantee that the case most worth flagging is the
  one that gets missed. It is NOTHING_ENCRYPTED below instead.

So: the exit code answers "what class of thing happened", `report.json` answers "how much".

Two codes are load-bearing beyond their number:

* **2 is the usage code and nothing else may take it.** argparse exits 2 on its own for a
  malformed command line, so assigning 2 to a sopack condition would make "you typed the command
  wrong" indistinguishable from that condition. `cli._reject_removed_flags` and `init-config`
  refusing to clobber a file map here too - they are usage mistakes, and before this module they
  landed on 1, reporting the most likely automation failure (a stale `--cipher`) as an internal
  error.
* **1 is the catch-all**, i.e. "sopack has a bug or hit something it does not model". Adding a
  code for a newly-modelled failure is always better than widening 1.

Anything that fires before the run directory exists (both code-2 paths) leaves NO run record -
the message is on stderr only. That is intentional: nothing was packed, so there is no run to
describe. See docs/TROUBLESHOOTING.md.
"""
from __future__ import annotations

OK = 0                  # at least one library was encrypted
INTERNAL = 1            # unhandled/unmodelled - the catch-all
USAGE = 2               # argparse, removed flags, init-config over an existing file
CONFIG = 3              # ConfigError: unreadable, unparseable or invalid config
INPUT = 4               # the input APK is missing, unreadable or not a zip
SELECTION = 5           # nothing matched libraries.include
NOTHING_ENCRYPTED = 6   # the pack ran but protected zero libraries
TOOLCHAIN = 7           # StubMissingError / ProvisionError: build artifacts or wb_keygen
INJECT = 8              # InjectError: injection, self-verify, 16 KB refusal
SIGNING = 9             # apksigner present but failed
OUTPUT = 10             # could not write the output APK

# The slug that goes in `report.json`'s "status" field, parallel to the code so a caller can
# branch on either. Keep these two in lockstep; tests/test_exitcodes.py pins that every code
# defined above has exactly one slug.
SLUGS = {
    OK: "ok",
    INTERNAL: "internal-error",
    USAGE: "usage-error",
    CONFIG: "config-error",
    INPUT: "input-error",
    SELECTION: "selection-error",
    NOTHING_ENCRYPTED: "nothing-encrypted",
    TOOLCHAIN: "toolchain-error",
    INJECT: "inject-error",
    SIGNING: "signing-error",
    OUTPUT: "output-error",
}


def slug(code: int) -> str:
    """The status slug for `code`, or a synthetic one for a code we do not know.

    Never raises: this is called while building a report for a run that already failed, and a
    KeyError here would replace a real diagnosis with a traceback from the reporting layer.
    """
    return SLUGS.get(code, f"unknown-{code}")
