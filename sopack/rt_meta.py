"""Pack/parse the two `--cipher wbaes` metadata regions. MUST match stub/sopk_rt.h exactly
(packed, little-endian).

Two artifacts, two regions:

  `TargetRegion` ('SRTT', 96-byte header + soname tail) is appended to each THIN per-target
  helper (`libsopk_rt_<target>.so`). Its ctor (stub/sopk_rt.c) locates it by magic.

  `WbRegion` ('SRTW', 24-byte header + wpass/blob tail) is appended to the ONE shared provider
  (`libsopk_wb.so`) per ABI. `sopk_wb_k` (stub/sopk_wb.c) locates it the same way.

v3 split them. Up to v2 a single region carried both, so every helper shipped its own ~455 KB
blob. v2 = key wrapping (wbcrypto 2.0.0); v1 carried a bare AES-CTR `iv` and relied on
`wbc_crypt_ctr`, which 2.0.0 deleted.

WARNING FOR ANYONE EDITING `TargetRegion`: v3 kept the header at 96 bytes and `_FMT` textually
identical — `pass_len`/`blob_len` were replaced by `flags`/`reserved` of the same widths. So
`HDR_SIZE == 96` and a literal-`_FMT` assertion do NOT detect v2/v3 drift. The **magic** is what
does; keep the `b"SRTT"` and version-3 assertions in tests/test_rt_meta.py.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .cipher import WRAPPED_KEY_BYTES

TARGET_REGION_MAGIC = 0x54545253   # bytes 'S','R','T','T' little-endian
WB_REGION_MAGIC = 0x57545253       # bytes 'S','R','T','W' little-endian
REGION_VERSION = 3                 # v3 = provider split; both ctors require an exact match

# Back-compat alias: plenty of call sites and docs say REGION_MAGIC meaning the target's.
REGION_MAGIC = TARGET_REGION_MAGIC

# The shared provider's DT_SONAME, and the single symbol it exports. Both live here so they can
# be renamed for string hygiene without touching the packer's guards.
#
# PROVIDER_SONAME is NOT cosmetic: each thin helper's DT_NEEDED string is whatever the linker
# recorded as the provider's DT_SONAME at Phase-4 time, so the provider must be linked with
# `-Wl,-soname,libsopk_wb.so` and the packer must never rename it. See stub/sopk_wb.c.
PROVIDER_SONAME = "libsopk_wb.so"
PROVIDER_ENTRY = "sopk_wb_k"
# Must equal SOPK_WB_ABI in stub/sopk_wb.h, which tracks SOPK_RT_REGION_VERSION. Passed on every
# provider call so a mismatched helper/provider PAIR fails cleanly on the first call.
PROVIDER_ABI = REGION_VERSION

# Opaque bytes each hand-built skeleton must contain, mirroring SOPK_RT_BUILD_MARKER_BYTES and
# SOPK_WB_BUILD_MARKER_BYTES in stub/sopk_rt.h. The skeletons are built by hand outside this
# repo, and a stale one is undiagnosable on device: the ctor's version gate finds no region and
# aborts with no indication that the cause is a stale build. elf_inject.py refuses a skeleton
# without them, turning that into a pack-time error that names the rebuild.
#
# The two values are deliberately DIFFERENT. With one shared marker, "fresh thin helper + stale
# provider" would pass both guards — and that mismatched pair is the real failure mode now that
# two artifacts must be rebuilt together.
#
# Bumped ONCE for the two changes that landed together: the wbcrypto 3.0.0 migration (the
# provider now calls wbc_blob_kdf_tier) and the v3 region split. See stub/sopk_rt.h.
HELPER_BUILD_MARKER = bytes((0x96, 0x02, 0xc8, 0xdb, 0x07, 0x61, 0xc4, 0xa8))
PROVIDER_BUILD_MARKER = bytes((0xe6, 0xe9, 0x03, 0xbf, 0xea, 0x5a, 0xf3, 0x40))
# Values that shipped before; a rebuild must not silently reuse one. Pinned by test_rt_meta.py.
SUPERSEDED_BUILD_MARKERS = (
    bytes.fromhex("1dc74b92a630e852"),
    bytes.fromhex("61eb361771ab71e2"),
)

# target header: magic,version | text_rva,text_size | wrapped | nonce16 | soname_len,flags,reserved
_FMT = "<IIQQ48s16sHHI"
HDR_SIZE = struct.calcsize(_FMT)
assert HDR_SIZE == 96, f"sopk_rt_region header drift: {HDR_SIZE} != 96"

# provider header: magic,version,blob_len | pass_len,flags | reserved0,reserved1
_WB_FMT = "<IIIHHII"
WB_HDR_SIZE = struct.calcsize(_WB_FMT)
assert WB_HDR_SIZE == 24, f"sopk_wb_region header drift: {WB_HDR_SIZE} != 24"


@dataclass
class TargetRegion:
    """Per-target metadata, appended to one thin helper. Carries no blob and no passphrase —
    those live once, in the shared provider's WbRegion."""
    text_rva: int
    text_size: int
    wrapped: bytes           # 48 bytes, exactly what wbc_wrap_key emits (see provision.py)
    nonce16: bytes           # 16 bytes: [0:12] ChaCha20 nonce, [12:16] counter (LE)
    soname: bytes            # target soname, matched by basename via dl_iterate_phdr
    version: int = REGION_VERSION

    def pack(self) -> bytes:
        assert len(self.wrapped) == WRAPPED_KEY_BYTES, (
            f"wrapped key must be {WRAPPED_KEY_BYTES} bytes, got {len(self.wrapped)}")
        assert len(self.nonce16) == 16
        assert len(self.soname) <= 0xFFFF
        hdr = struct.pack(
            _FMT, TARGET_REGION_MAGIC, self.version, self.text_rva, self.text_size,
            self.wrapped, self.nonce16, len(self.soname), 0, 0,
        )
        return hdr + self.soname

    @classmethod
    def unpack(cls, data: bytes) -> "TargetRegion":
        # Check the magic before the size: a provider region is shorter than this header, so
        # unpacking first would raise struct.error and hide which artifact was passed.
        if len(data) >= 4 and data[:4] == WB_REGION_MAGIC.to_bytes(4, "little"):
            raise ValueError(
                "this is a PROVIDER region ('SRTW'), not a target region ('SRTT') — the "
                "two artifacts were mixed up")
        if len(data) < HDR_SIZE:
            raise ValueError(
                f"truncated sopk_rt_region: {len(data)} bytes, need {HDR_SIZE}")
        (magic, version, text_rva, text_size, wrapped, nonce16,
         soname_len, _flags, _reserved) = struct.unpack(_FMT, data[:HDR_SIZE])
        if magic != TARGET_REGION_MAGIC:
            if magic == WB_REGION_MAGIC:
                raise ValueError(
                    "this is a PROVIDER region ('SRTW'), not a target region ('SRTT') — the "
                    "two artifacts were mixed up")
            raise ValueError(f"bad sopk_rt_region magic 0x{magic:08x}")
        _check_version(version, "sopk_rt_region")
        return cls(text_rva, text_size, wrapped, nonce16,
                   data[HDR_SIZE:HDR_SIZE + soname_len], version)


@dataclass
class WbRegion:
    """The shared provider's metadata: one sealed blob and one whitened passphrase per (pack,
    ABI). They MUST stay in the same artifact — the whitening key is derived from the blob's own
    first `cipher.WHITEN_SPAN` bytes (see cipher.whiten_pass)."""
    wpass: bytes
    blob: bytes
    version: int = REGION_VERSION

    def pack(self) -> bytes:
        assert len(self.wpass) <= 0xFFFF
        hdr = struct.pack(_WB_FMT, WB_REGION_MAGIC, self.version, len(self.blob),
                          len(self.wpass), 0, 0, 0)
        return hdr + self.wpass + self.blob

    @classmethod
    def unpack(cls, data: bytes) -> "WbRegion":
        if len(data) < WB_HDR_SIZE:
            raise ValueError(
                f"truncated sopk_wb_region: {len(data)} bytes, need {WB_HDR_SIZE}")
        (magic, version, blob_len, pass_len,
         _flags, _r0, _r1) = struct.unpack(_WB_FMT, data[:WB_HDR_SIZE])
        if magic != WB_REGION_MAGIC:
            if magic == TARGET_REGION_MAGIC:
                raise ValueError(
                    "this is a TARGET region ('SRTT'), not a provider region ('SRTW') — the "
                    "two artifacts were mixed up")
            raise ValueError(f"bad sopk_wb_region magic 0x{magic:08x}")
        _check_version(version, "sopk_wb_region")
        off = WB_HDR_SIZE
        wpass = data[off:off + pass_len]; off += pass_len
        return cls(wpass, data[off:off + blob_len], version)


def _check_version(version: int, what: str) -> None:
    if version != REGION_VERSION:
        # The on-device ctor gates on an exact version match, and a mismatch means its self-scan
        # matches no segment at all: it aborts naming "no region" rather than "wrong version".
        # So it does NOT fail open — but this host-side check is the only place the real cause
        # is stated.
        raise ValueError(
            f"{what} version {version} != {REGION_VERSION} — the skeletons and the packer are "
            f"from different versions; rebuild both (docs/wbaes-verification.md Phase 4)")


# Historical name. v2 packed target fields and the blob together; v3 split them, so there is no
# single "Region" any more and the alias would silently accept the wrong one.
Region = TargetRegion
