"""Pack/parse the `sopk_rt_region` metadata block for `--cipher wbaes`. MUST match
stub/sopk_rt.h exactly (packed, little-endian, 96-byte header + variable tail).

The packer appends the packed region as a read-only PT_LOAD to the per-target helper
(`libsopk_rt_<target>.so`); the helper's constructor (stub/sopk_rt.c) locates it by the
magic and parses this same layout. See stub/sopk_rt.h for the contract and the whitening
note (the passphrase is whitened with a key derived from the sealed blob's first bytes).

v2 (wbcrypto 2.0.0, key wrapping): the region carries `wrapped` — the white-box-wrapped
32-byte session key — plus the ChaCha20 `nonce16` that key is used with. v1 carried a
bare AES-CTR `iv` and relied on `wbc_crypt_ctr`, which 2.0.0 deleted."""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .cipher import SESSION_KEY_BYTES, WRAPPED_KEY_BYTES  # noqa: F401 — re-exported

REGION_MAGIC = 0x52545253    # bytes 'S','R','T','R' little-endian
REGION_VERSION = 2           # v2 = key wrapping; the helper requires an exact match

# Opaque bytes the helper skeleton must contain, mirroring SOPK_RT_BUILD_MARKER_BYTES in
# stub/sopk_rt.h. The skeleton is built by hand outside this repo, and a stale one fails
# open SILENTLY on device (the ctor's version gate finds no region, so the target runs
# encrypted .text and crashes). elf_inject.py:_emit_helper refuses a skeleton without
# these, turning that into a pack-time error. Bump both sides together.
HELPER_BUILD_MARKER = bytes((0x1d, 0xc7, 0x4b, 0x92, 0xa6, 0x30, 0xe8, 0x52))

# header: magic,version | text_rva,text_size | wrapped | nonce16 | soname_len,pass_len,blob_len
_FMT = "<IIQQ48s16sHHI"
HDR_SIZE = struct.calcsize(_FMT)
assert HDR_SIZE == 96, f"sopk_rt_region header drift: {HDR_SIZE} != 96"


@dataclass
class Region:
    text_rva: int
    text_size: int
    wrapped: bytes           # 48 bytes, exactly what wbc_wrap_key emits (see provision.py)
    nonce16: bytes           # 16 bytes: [0:12] ChaCha20 nonce, [12:16] counter (LE)
    soname: bytes            # target soname, matched by basename via dl_iterate_phdr
    wpass: bytes             # whitened passphrase (self-inverse; see cipher.whiten_pass)
    blob: bytes              # sealed white-box blob
    version: int = REGION_VERSION

    def pack(self) -> bytes:
        assert len(self.wrapped) == WRAPPED_KEY_BYTES, (
            f"wrapped key must be {WRAPPED_KEY_BYTES} bytes, got {len(self.wrapped)}")
        assert len(self.nonce16) == 16
        assert len(self.soname) <= 0xFFFF and len(self.wpass) <= 0xFFFF
        hdr = struct.pack(
            _FMT, REGION_MAGIC, self.version, self.text_rva, self.text_size,
            self.wrapped, self.nonce16,
            len(self.soname), len(self.wpass), len(self.blob),
        )
        return hdr + self.soname + self.wpass + self.blob

    @classmethod
    def unpack(cls, data: bytes) -> "Region":
        (magic, version, text_rva, text_size, wrapped, nonce16,
         soname_len, pass_len, blob_len) = struct.unpack(_FMT, data[:HDR_SIZE])
        if magic != REGION_MAGIC:
            raise ValueError(f"bad sopk_rt_region magic 0x{magic:08x}")
        if version != REGION_VERSION:
            # The on-device ctor gates on an exact version match and fails open silently,
            # so catching the mismatch here (host side) is the only loud diagnostic.
            raise ValueError(
                f"sopk_rt_region version {version} != {REGION_VERSION} — the helper "
                "skeleton and the packer are from different versions")
        off = HDR_SIZE
        soname = data[off:off + soname_len]; off += soname_len
        wpass = data[off:off + pass_len]; off += pass_len
        blob = data[off:off + blob_len]; off += blob_len
        return cls(text_rva, text_size, wrapped, nonce16, soname, wpass, blob, version)
