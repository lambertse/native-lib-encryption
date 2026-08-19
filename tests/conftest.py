"""Container fixtures shared across the test modules.

There are two of them and they exist because `sopack` now takes two container formats, decided by
what is INSIDE the file (`sopack.container.detect`). Before that, three test modules each carried
their own near-identical `_mkapk`, and the fourth wrote a 22-byte empty zip - which stopped being
a usable stand-in the moment "is this an APK?" became a real question the packer asks.

Deliberately NO autouse fixtures here. `test_exitcodes.py` and `test_diag.py` each define their
own autouse teardown for `diag`'s module state, and those must stay per-module: an autouse fixture
in a conftest applies to every test file in the directory, which would silently change the
isolation regime of modules that never asked for it.
"""
from __future__ import annotations

import zipfile

# What a not-quite-ELF library body looks like. Long enough that a truncation bug is visible,
# short enough to keep the fixtures tiny. Real injection tests use tests/fixtures/mini_arm64.so.
LIB_BODY = b"\x7fELF-not-really"


def mkapk(path, names=(), *, manifest=b"\x00", body=LIB_BODY):
    """A minimal but genuinely detectable APK: a ROOT AndroidManifest.xml plus `names`.

    The manifest is what `container.detect` keys on, so it is not decoration - drop it and the
    pack correctly refuses the file as neither an APK nor a bundle.
    """
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        for n in names:
            z.writestr(n, body)
    return str(path)


def mkaab(path, names=(), *, body=LIB_BODY, deflate=True):
    """A minimal but genuinely detectable AAB.

    Mirrors the real shape closely enough for the parts sopack touches: a ROOT `BundleConfig.pb`
    (the detection marker), a per-module manifest at `<module>/manifest/AndroidManifest.xml` in
    place of a root one, and libraries at `<module>/lib/<abi>/*.so`. `names` are full entry names,
    so a caller writes `base/lib/arm64-v8a/libfoo.so` and can add a second module.

    Entries are DEFLATED by default because that is what bundletool emits - every `.so` in a real
    bundle is compressed - and preserving that is one of the five things the container descriptor
    decides.
    """
    comp = zipfile.ZIP_DEFLATED if deflate else zipfile.ZIP_STORED
    modules = {n.split("/", 1)[0] for n in names} or {"base"}
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("BundleConfig.pb", b"\x0a\x08\x12\x06" + b"1.18.1")
        for mod in sorted(modules):
            z.writestr(f"{mod}/manifest/AndroidManifest.xml", b"\x0a\x08proto")
            z.writestr(f"{mod}/dex/classes.dex", b"dex" * 40, comp)
        for n in names:
            z.writestr(n, body, comp)
    return str(path)


# For tests that run the same assertion against both formats. The keys are container.Container.kind
# values, so a parametrized test can use one as its id and hand the other to `report.json`.
BUILDERS = {"apk": mkapk, "aab": mkaab}
