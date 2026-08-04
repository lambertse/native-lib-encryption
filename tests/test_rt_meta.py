"""Pin the sopk_rt_region layout (sopack/rt_meta.py ⇄ stub/sopk_rt.h). If this drifts,
the on-device helper parses garbage. Golden-vector + round-trip."""
import os
import struct

import pytest

from sopack import cipher
from sopack.rt_meta import (HDR_SIZE, HELPER_BUILD_MARKER, REGION_MAGIC, REGION_VERSION,
                            WRAPPED_KEY_BYTES, Region)


def test_header_size_and_magic():
    assert HDR_SIZE == 96                     # must equal sizeof(sopk_rt_region)
    assert REGION_MAGIC == 0x52545253         # 'S','R','T','R' little-endian
    assert REGION_VERSION == 2                # v2 = wbcrypto 2.0.0 key wrapping
    assert WRAPPED_KEY_BYTES == 48            # WBC_WRAPPED_KEY_BYTES: 16 IV + 32 key


def test_build_marker_matches_the_c_header():
    """The marker the packer greps for must be the bytes sopk_rt.c actually embeds. These
    live in two languages, so read the C header rather than trusting the Python copy."""
    hdr = os.path.join(os.path.dirname(__file__), os.pardir, "stub", "sopk_rt.h")
    with open(hdr) as f:
        text = f.read()
    line = next(ln for ln in text.splitlines() if "SOPK_RT_BUILD_MARKER_BYTES" in ln
                and "{" in ln)
    body = line[line.index("{") + 1:line.rindex("}")]
    from_c = bytes(int(tok.strip(), 16) for tok in body.split(",") if tok.strip())
    assert from_c == HELPER_BUILD_MARKER
    assert f"SOPK_RT_BUILD_MARKER_LEN  {len(HELPER_BUILD_MARKER)}u" in text


def test_region_golden_layout():
    wrapped = bytes.fromhex("00112233445566778899aabbccddeeff") + bytes(range(32))
    nonce16 = bytes.fromhex("a1a2a3a4a5a6a7a8a9aaabac") + b"\x00\x00\x00\x00"
    r = Region(
        text_rva=0x679f0, text_size=0x123,
        wrapped=wrapped, nonce16=nonce16,
        soname=b"libsopk_rt_libfoo.so", wpass=b"\xaa\xbb\xcc", blob=b"BLOBDATA",
    )
    packed = r.pack()
    # fixed 96-byte header, then soname||wpass||blob
    assert packed[:4] == b"SRTR"
    assert len(packed) == HDR_SIZE + len(r.soname) + len(r.wpass) + len(r.blob)
    # header fields at their offsets (literal format string, so drift in _FMT is caught)
    magic, ver, trva, tsz, wr, nn, snl, pl, bl = struct.unpack("<IIQQ48s16sHHI", packed[:96])
    assert (ver, trva, tsz, wr, nn, snl, pl, bl) == (
        2, 0x679f0, 0x123, wrapped, nonce16, 20, 3, 8)
    # round-trip
    back = Region.unpack(packed)
    assert (back.text_rva, back.text_size, back.wrapped, back.nonce16, back.soname,
            back.wpass, back.blob) == (r.text_rva, r.text_size, r.wrapped, r.nonce16,
                                       r.soname, r.wpass, r.blob)


def test_unpack_rejects_a_foreign_version():
    """The on-device ctor gates on an exact version match and then fails open SILENTLY, so
    the host-side check is the only loud diagnostic for a packer/skeleton mismatch."""
    r = Region(text_rva=0x1000, text_size=64, wrapped=bytes(48),
               nonce16=bytes(16), soname=b"libx.so", wpass=b"\x01", blob=b"B" * 32)
    packed = bytearray(r.pack())
    packed[4:8] = struct.pack("<I", 1)                  # pretend it is a v1 region
    with pytest.raises(ValueError, match="version 1"):
        Region.unpack(bytes(packed))


def test_pack_rejects_a_wrong_length_wrapped_key():
    """A short wrapped key would be read as a fixed-size field on device — a garbage
    session key rather than a parse error — so refuse it here."""
    r = Region(text_rva=0x1000, text_size=64, wrapped=bytes(47),
               nonce16=bytes(16), soname=b"libx.so", wpass=b"\x01", blob=b"B" * 32)
    with pytest.raises(AssertionError, match="48 bytes"):
        r.pack()


def test_region_carries_whitened_pass_roundtrip():
    """The passphrase in the region is whitened off the blob; the helper de-whitens with
    the same contract (cipher.whiten_pass, keyed on blob[:WHITEN_SPAN])."""
    blob = os.urandom(2048)
    plain = b"per-lib-passphrase"
    wpass = cipher.whiten_pass(plain, blob)
    r = Region(text_rva=0x1000, text_size=64, wrapped=os.urandom(48),
               nonce16=os.urandom(16), soname=b"libx.so", wpass=wpass, blob=blob)
    back = Region.unpack(r.pack())
    assert cipher.whiten_pass(back.wpass, back.blob) == plain
