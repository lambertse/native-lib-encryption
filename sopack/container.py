"""What kind of zip we were handed - an APK or an Android App Bundle - and the five things
that differ between them.

sopack takes an `.aab` through the SAME code path as an `.apk`, with no flag and no config key:
`repackage` asks `detect()` what it is opening and consults the returned descriptor at exactly
five points. Everything else - selection, provisioning, injection, self-verification, run
records - is format-blind, because it operates on a `.so` and a `.so` does not care what zip it
travelled in.

Why a descriptor instead of `if is_aab:` sprinkled through apk.py: the differences are not one
decision, they are five (below), and they are not independent - skipping alignment and skipping
signing both change which temp file is the finished artifact. Collecting them in one frozen
object is what keeps `repackage()` a single path.

**The two entry patterns are deliberately separate regexes, not one with an optional prefix.**
An APK's libraries are at `lib/<abi>/<name>.so` and nothing else counts; a bundle's are at
`<module>/lib/<abi>/<name>.so` and the module segment is REQUIRED. Writing the union as
`^(?:([^/]+)/)?lib/…` looks tidier and is wrong: it would make sopack start selecting nested
entries such as `assets/lib/arm64-v8a/foo.so` in APKs where they have always been ignored -
a silent widening of what gets encrypted, across every APK anyone has already packed.
`tests/test_lib_select.py` pins that an APK's nested `.so` is not even a candidate.

Detection is by CONTENT, never by extension:

  * a root `BundleConfig.pb`      -> AAB   (bundletool writes exactly one, always at the root)
  * a root `AndroidManifest.xml`  -> APK   (a bundle's manifest is at <module>/manifest/, in
                                            protobuf form, never at the root)

An extension is a naming convention, not a fact about the file; a `.zip` copy of a bundle or an
`.apk` that is really a bundle both have to work, and getting it wrong is expensive (the packer
would rewrite ~150 MB before failing). Extension is used for ONE thing, in cli.py: warning that
the `-o` name disagrees with what the input turned out to be.
"""
from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass

from .errors import InputError

# The marker entries detection keys on, at the zip root.
AAB_MARKER = "BundleConfig.pb"
APK_MARKER = "AndroidManifest.xml"


@dataclass(frozen=True)
class Container:
    """One row of format-dependent behaviour. Frozen: these are constants, not settings."""

    kind: str            # "apk" | "aab" - what report.json records
    noun: str            # "APK" | "AAB" - what messages say
    lib_re: re.Pattern   # named groups: `abi`, `so`, and `mod` iff has_module
    has_module: bool     # do entries carry a leading <module>/ segment?
    lib_shape: str       # the pattern as a human writes it, for error messages
    store_libs: bool     # write injected libraries ZIP_STORED?
    zipalign: bool       # 16 KB-align the container afterwards?
    sign: bool           # may sopack sign this container at all?


APK = Container(
    kind="apk",
    noun="APK",
    # Byte-for-byte the pattern this tool has always used (it was apk._LIB_RE), now with named
    # groups. Do not relax it - see the module docstring.
    lib_re=re.compile(r"^lib/(?P<abi>[^/]+)/(?P<so>[^/]+\.so)$"),
    has_module=False,
    lib_shape="lib/<abi>/*.so",
    # STORED + 16 KB-aligned is what makes the library page-mappable straight out of the zip
    # under `extractNativeLibs="false"`. See docs/technical/PAGE-ALIGNMENT.md "Step 0".
    store_libs=True,
    zipalign=True,
    sign=True,
)

AAB = Container(
    kind="aab",
    noun="AAB",
    lib_re=re.compile(r"^(?P<mod>[^/]+)/lib/(?P<abi>[^/]+)/(?P<so>[^/]+\.so)$"),
    has_module=True,
    lib_shape="<module>/lib/<abi>/*.so",
    # A bundle is not installed; bundletool reads it and GENERATES the APKs, choosing their
    # compression and page alignment itself (`BundleConfig.pb`'s
    # `optimizations.uncompress_native_libraries`). Whatever we do to this zip's entry offsets
    # is discarded at that point, so forcing STORED would only inflate the artifact - a real
    # bundle's `.so` entries are all DEFLATED, and uncompressed they run to ~100 MB.
    store_libs=False,
    zipalign=False,
    # sopack never signs a bundle. apksigner CANNOT ("Missing AndroidManifest.xml" - a bundle
    # has no root manifest), a bundle is JAR-signed, and Play verifies the app's UPLOAD key,
    # which sopack has no business holding. So the output is unsigned by design and the operator
    # signs it with `jarsigner`. See the note in apk.py's signing block.
    sign=False,
)

_BY_KIND = {c.kind: c for c in (APK, AAB)}

# Display-only: pull the ABI out of an entry that already matched one of the patterns above.
# Deliberately shape-agnostic (it anchors on the `lib/` segment) because its callers - the CLI
# summary and report.py's per-ABI counts - are handed entry strings with no descriptor alongside.
_ABI_RE = re.compile(r"(?:^|/)lib/([^/]+)/[^/]+\.so$")


def of_kind(kind: str) -> Container:
    """The descriptor for a recorded `kind` string. For a library caller round-tripping one."""
    try:
        return _BY_KIND[kind]
    except KeyError:
        raise ValueError(f"unknown container kind {kind!r}; expected one of "
                         f"{', '.join(sorted(_BY_KIND))}") from None


def detect(path: str) -> Container:
    """Classify `path` by its contents. Raises InputError if it is neither.

    `zipfile.BadZipFile` is left to propagate - cli.py already maps it to the same exit code
    (INPUT), and "this is not a zip at all" is a different sentence than "this zip is neither an
    APK nor a bundle".
    """
    with zipfile.ZipFile(path, "r") as z:
        names = set(z.namelist())
    if AAB_MARKER in names:
        return AAB
    if APK_MARKER in names:
        return APK
    raise InputError(
        f"{path} is a zip, but neither an APK nor an Android App Bundle: it has no root "
        f"{APK_MARKER!r} (APK) and no root {AAB_MARKER!r} (AAB). If this is an APK, it is "
        f"missing its manifest; if it is a bundle, it was not produced by bundletool.")


def abi_of(entry: str) -> str:
    """The ABI directory of a native-library entry, or "?" if the shape is unrecognised.

    One implementation for both container shapes, and one for the whole tool: this used to be
    copy-pasted into cli.py and report.py as `entry.split("/")[1]`, which returns the literal
    "lib" for a bundle's `base/lib/arm64-v8a/x.so` - so a packed bundle's per-ABI summary and
    `report.json`'s `per_abi` both counted under an ABI named "lib".
    """
    m = _ABI_RE.search(entry)
    return m.group(1) if m else "?"
