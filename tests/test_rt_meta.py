"""Pin the sopk_rt_region layout (sopack/rt_meta.py ⇄ stub/sopk_rt.h). If this drifts,
the on-device helper parses garbage. Golden-vector + round-trip."""
import os
import re
import struct

import pytest

from sopack import cipher
from sopack.rt_meta import (
    HDR_SIZE,
    HELPER_BUILD_MARKER,
    PROVIDER_ABI,
    PROVIDER_BUILD_MARKER,
    PROVIDER_BUILD_MARKER,
    REGION_MAGIC,
    REGION_VERSION,
    SUPERSEDED_BUILD_MARKERS,
    TARGET_REGION_MAGIC,
    WB_HDR_SIZE,
    WB_REGION_MAGIC,
    WRAPPED_KEY_BYTES,
    TargetRegion,
    WbRegion,
)


def _c_defines(text: str) -> str:
    """Splice backslash line-continuations so a #define is one logical line.

    clang-format wraps SOPK_*_BUILD_MARKER_BYTES at 80 columns, so the macro name
    and its {0x..} initialiser need not share a physical line. Parsing per-line was
    silently formatting-dependent and broke on a pure reflow.
    """
    return re.sub(r"\\\s*\n", " ", text)


def _c_marker(text: str, macro: str) -> bytes:
    m = re.search(
        rf"#\s*define\s+{macro}\s*\{{([^}}]*)\}}",
        _c_defines(text),
    )
    assert m, f"{macro} not found as a brace initialiser in stub/sopk_rt.h"
    return bytes(
        int(t, 16)
        for t in re.findall(r"0x[0-9a-fA-F]+", m.group(1))
    )


def _c_len(text: str, macro: str) -> int:
    m = re.search(
        rf"#\s*define\s+{macro}\s+(\d+)u?\b",
        _c_defines(text),
    )
    assert m, f"{macro} not found in stub/sopk_rt.h"
    return int(m.group(1))


def test_header_sizes_and_magics():
    """The two magics MUST differ, and this is the assertion that gates v2->v3 drift.

    v3 kept the target header at 96 bytes and `_FMT` textually identical
    (`pass_len`/`blob_len` became `flags`/`reserved`, same widths), so a size or
    format-string check passes either way. Only the magic distinguishes them.
    """
    assert HDR_SIZE == 96                     # must equal sizeof(sopk_rt_region)
    assert WB_HDR_SIZE == 24                  # must equal sizeof(sopk_wb_region)
    assert TARGET_REGION_MAGIC == 0x54545253  # 'S','R','T','T' little-endian
    assert WB_REGION_MAGIC == 0x57545253      # 'S','R','T','W' little-endian
    assert TARGET_REGION_MAGIC != WB_REGION_MAGIC
    assert REGION_MAGIC == TARGET_REGION_MAGIC        # the historical alias

    # v3 = the provider split: the blob and passphrase moved out of every
    # per-target region into the ONE shared provider per ABI.
    assert REGION_VERSION == 3
    assert PROVIDER_ABI == REGION_VERSION     # SOPK_WB_ABI tracks it
    assert WRAPPED_KEY_BYTES == 48            # 16 IV + 32 key


def test_build_marker_matches_the_c_header():
    """The marker the packer greps for must be the bytes sopk_rt.c actually embeds.

    Parse the header in a formatting-independent way so clang-format reflows do
    not break the test.
    """
    hdr = os.path.join(os.path.dirname(__file__), os.pardir, "stub", "sopk_rt.h")
    with open(hdr) as f:
        text = f.read()

    # Helper marker
    assert _c_marker(text, "SOPK_RT_BUILD_MARKER_BYTES") == HELPER_BUILD_MARKER
    assert _c_len(text, "SOPK_RT_BUILD_MARKER_LEN") == len(HELPER_BUILD_MARKER)

    # Provider marker: the other half of the pair
    assert _c_marker(text, "SOPK_WB_BUILD_MARKER_BYTES") == PROVIDER_BUILD_MARKER
    assert _c_len(text, "SOPK_WB_BUILD_MARKER_LEN") == len(PROVIDER_BUILD_MARKER)

    # The two markers must be distinct.
    assert HELPER_BUILD_MARKER != PROVIDER_BUILD_MARKER


def test_build_marker_is_not_a_superseded_value():
    """The test above only proves the two languages agree — it passes automatically
    once both sides are edited, so on its own it does not gate a bump at all.
    This does: the marker must differ from every value that ever shipped, and
    each retired value must stay documented in the C header so a future bump
    cannot silently recycle one.
    """
    hdr = os.path.join(os.path.dirname(__file__), os.pardir, "stub", "sopk_rt.h")
    with open(hdr) as f:
        text = f.read()

    assert SUPERSEDED_BUILD_MARKERS, "the superseded list must not be emptied"

    for old in SUPERSEDED_BUILD_MARKERS:
        assert HELPER_BUILD_MARKER != old, (
            f"build marker reuses retired value {old.hex()}"
        )
        assert old.hex() in text, (
            f"retired marker {old.hex()} is missing from stub/sopk_rt.h's "
            f"superseded note; keep it recorded so the next bump cannot reuse it"
        )


def test_target_region_golden_layout():
    wrapped = bytes.fromhex("00112233445566778899aabbccddeeff") + bytes(range(32))
    nonce16 = bytes.fromhex("a1a2a3a4a5a6a7a8a9aaabac") + b"\x00\x00\x00\x00"

    r = TargetRegion(
        text_rva=0x679f0,
        text_size=0x123,
        wrapped=wrapped,
        nonce16=nonce16,
        soname=b"libsopk_rt_libfoo.so",
    )

    packed = r.pack()

    assert packed[:4] == b"SRTT"
    assert len(packed) == HDR_SIZE + len(r.soname)

    magic, ver, trva, tsz, wr, nn, snl, flags, reserved = struct.unpack(
        "<IIQQ48s16sHHI", packed[:96]
    )

    assert (ver, trva, tsz, wr, nn, snl) == (
        3,
        0x679F0,
        0x123,
        wrapped,
        nonce16,
        20,
    )
    assert (flags, reserved) == (0, 0)

    back = TargetRegion.unpack(packed)
    assert (
        back.text_rva,
        back.text_size,
        back.wrapped,
        back.nonce16,
        back.soname,
    ) == (
        r.text_rva,
        r.text_size,
        r.wrapped,
        r.nonce16,
        r.soname,
    )


def test_provider_region_golden_layout():
    w = WbRegion(wpass=b"\xaa\xbb\xcc", blob=b"BLOBDATA")

    packed = w.pack()
    assert packed[:4] == b"SRTW"
    assert len(packed) == WB_HDR_SIZE + len(w.wpass) + len(w.blob)

    magic, ver, bl, pl, flags, r0, r1 = struct.unpack("<IIIHHII", packed[:24])

    assert (ver, bl, pl) == (3, 8, 3)
    assert (flags, r0, r1) == (0, 0, 0)

    back = WbRegion.unpack(packed)
    assert (back.wpass, back.blob) == (w.wpass, w.blob)


def test_each_region_kind_rejects_the_other():
    """The magics differ so a mixed-up pair of artifacts is a clean error rather
    than a parse of garbage.
    """
    tgt = TargetRegion(
        text_rva=0x1000,
        text_size=64,
        wrapped=bytes(48),
        nonce16=bytes(16),
        soname=b"libx.so",
    ).pack()

    wb = WbRegion(wpass=b"\x01", blob=b"B" * 32).pack()

    with pytest.raises(ValueError, match="PROVIDER region"):
        TargetRegion.unpack(wb)

    with pytest.raises(ValueError, match="TARGET region"):
        WbRegion.unpack(tgt)


def test_unpack_rejects_a_foreign_version():
    """The host-side check should name version skew explicitly."""
    for kind, packed in (
        (
            "target",
            TargetRegion(
                text_rva=0x1000,
                text_size=64,
                wrapped=bytes(48),
                nonce16=bytes(16),
                soname=b"libx.so",
            ).pack(),
        ),
        (
            "provider",
            WbRegion(wpass=b"\x01", blob=b"B" * 32).pack(),
        ),
    ):
        buf = bytearray(packed)
        buf[4:8] = struct.pack("<I", 1)

        cls = TargetRegion if kind == "target" else WbRegion

        with pytest.raises(ValueError, match="version 1"):
            cls.unpack(bytes(buf))


def test_a_v2_shaped_region_is_rejected():
    """A v2 region has the old magic ('SRTR') and version 2."""
    v2 = struct.pack(
        "<IIQQ48s16sHHI",
        0x52545253,
        2,
        0x1000,
        64,
        bytes(48),
        bytes(16),
        7,
        1,
        32,
    ) + b"libx.so" + b"\x01" + b"B" * 32

    with pytest.raises(ValueError, match="magic"):
        TargetRegion.unpack(v2)


def test_pack_rejects_a_wrong_length_wrapped_key():
    """A short wrapped key would be read as a fixed-size field on device."""
    r = TargetRegion(
        text_rva=0x1000,
        text_size=64,
        wrapped=bytes(47),
        nonce16=bytes(16),
        soname=b"libx.so",
    )

    with pytest.raises(AssertionError, match="48 bytes"):
        r.pack()


def test_provider_region_carries_whitened_pass_roundtrip():
    """The passphrase is whitened off the blob and both ship in the provider."""
    blob = os.urandom(cipher.WHITEN_SPAN + 64)
    plain = b"per-pack-passphrase"

    wpass = cipher.whiten_pass(plain, blob)
    w = WbRegion.unpack(WbRegion(wpass=wpass, blob=blob).pack())

    assert w.blob == blob
    assert cipher.whiten_pass(w.wpass, w.blob) == plain
