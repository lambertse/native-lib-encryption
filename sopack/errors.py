"""Exceptions shared across layers, so the CLI can tell three unrelated failures apart.

`FileNotFoundError` was doing triple duty, and because it is also an `OSError` subclass it
shadowed everything more general in `cli._CODE_FOR`. All three of these reported themselves as
"the input APK is missing":

* the input APK really is missing            -> `InputError`      -> exit 4
* a HOST TOOL is missing (apksigner, keytool, zipalign, wb_keygen) -> `ToolMissingError` -> exit 7
* the OUTPUT path cannot be written          -> plain OSError     -> exit 10

That mattered most for `wb_keygen`: "could not find a host wb_keygen" is the first section of
docs/TROUBLESHOOTING.md and the most-hit failure on a fresh checkout, and reporting it as an
input error sends the reader to look at their APK instead of at their toolchain.

Both subclass `FileNotFoundError` deliberately, so every pre-existing `except FileNotFoundError`
keeps catching them - notably `apk.repackage`'s best-effort signing path, which demotes a missing
apksigner to a warning rather than failing the pack.

This module imports nothing from sopack, so it can be imported from any layer without a cycle.
"""
from __future__ import annotations


class ToolMissingError(FileNotFoundError):
    """A host tool sopack shells out to is not installed or not findable.

    Distinct from `stubs.StubMissingError` (a build ARTIFACT is absent) even though both map to
    exit 7: one is fixed by installing an SDK or a JDK, the other by running a build script. The
    message says which.
    """


class InputError(FileNotFoundError):
    """The input APK is missing, unreadable, or not a file.

    Raised by an explicit up-front check rather than inferred from wherever the first open()
    happens to fail, because "which path was this about?" is not recoverable from an errno after
    the fact - and getting it wrong is how an unwritable OUTPUT directory came to be reported as a
    missing input.
    """
