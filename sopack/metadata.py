"""Pack/parse the `sopk_decinfo` record. MUST match stub/decinfo.h exactly (packed,
little-endian, 128 bytes)."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

MAGIC = 0x4B504F53  # "SOPK" little-endian
VERSION = 1

# flags
FLAG_CHAIN_INIT = 1 << 0
FLAG_NEED_ICACHE = 1 << 1
FLAG_LOG = 1 << 2

# layout: magic,version,cipher,flags | delta_text,text_size,delta_init | key,nonce,reserved
_FMT = "<IIIiqQq32s16s40s"
SIZE = struct.calcsize(_FMT)
assert SIZE == 128, f"decinfo layout drift: {SIZE} != 128"


@dataclass
class DecInfo:
    cipher_id: int
    flags: int
    delta_text: int          # text_rva - decinfo_rva (signed)
    text_size: int
    delta_init: int          # orig_init_rva - decinfo_rva (signed); 0 if no chain
    key: bytes               # 32 bytes
    nonce: bytes             # 16 bytes
    version: int = VERSION
    reserved: bytes = field(default=b"\x00" * 40)

    def pack(self) -> bytes:
        assert len(self.key) == 32 and len(self.nonce) == 16
        return struct.pack(
            _FMT, MAGIC, self.version, self.cipher_id, self.flags,
            self.delta_text, self.text_size, self.delta_init,
            self.key, self.nonce, self.reserved,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "DecInfo":
        (magic, version, cipher_id, flags, delta_text, text_size,
         delta_init, key, nonce, reserved) = struct.unpack(_FMT, data[:SIZE])
        if magic != MAGIC:
            raise ValueError(f"bad decinfo magic 0x{magic:08x}")
        return cls(cipher_id, flags, delta_text, text_size, delta_init,
                   key, nonce, version, reserved)
