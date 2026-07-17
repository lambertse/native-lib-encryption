"""Stream ciphers for encrypting .so `.text`. MUST match stub/stub_cipher.h byte for
byte, because the desktop side encrypts and the injected stub decrypts with the same
keystream.

Pure-Python (no external crypto dependency) so the tool has a small footprint; the
volumes involved (a `.text` section) are tiny.
"""
from __future__ import annotations

import os
import struct

CIPHER_XOR = 0
CIPHER_CHACHA20 = 1

CIPHER_IDS = {"xor": CIPHER_XOR, "chacha20": CIPHER_CHACHA20}


def _xor_apply(buf: bytearray, key: bytes) -> None:
    for i in range(len(buf)):
        buf[i] ^= key[i & 31]


def _rotl32(x: int, c: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF


def _quarter(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl32(s[b] ^ s[c], 7)


def _chacha20_block(state: list) -> bytes:
    x = list(state)
    for _ in range(10):
        _quarter(x, 0, 4, 8, 12)
        _quarter(x, 1, 5, 9, 13)
        _quarter(x, 2, 6, 10, 14)
        _quarter(x, 3, 7, 11, 15)
        _quarter(x, 0, 5, 10, 15)
        _quarter(x, 1, 6, 11, 12)
        _quarter(x, 2, 7, 8, 13)
        _quarter(x, 3, 4, 9, 14)
    out = bytearray()
    for i in range(16):
        out += struct.pack("<I", (x[i] + state[i]) & 0xFFFFFFFF)
    return bytes(out)


def _chacha20_apply(buf: bytearray, key: bytes, nonce16: bytes) -> None:
    """nonce16 layout matches the stub: [0:12]=nonce, [12:16]=initial counter (LE)."""
    const = struct.unpack("<4I", b"expand 32-byte k")
    k = struct.unpack("<8I", key)
    counter = struct.unpack("<I", nonce16[12:16])[0]
    n = struct.unpack("<3I", nonce16[0:12])
    off = 0
    while off < len(buf):
        state = [const[0], const[1], const[2], const[3],
                 k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7],
                 counter & 0xFFFFFFFF, n[0], n[1], n[2]]
        ks = _chacha20_block(state)
        chunk = min(64, len(buf) - off)
        for i in range(chunk):
            buf[off + i] ^= ks[i]
        off += chunk
        counter = (counter + 1) & 0xFFFFFFFF


def apply_cipher(cipher_id: int, data: bytes, key: bytes, nonce16: bytes) -> bytes:
    """Encrypt/decrypt (identical for a stream cipher). Length-preserving."""
    buf = bytearray(data)
    if cipher_id == CIPHER_CHACHA20:
        _chacha20_apply(buf, key, nonce16)
    elif cipher_id == CIPHER_XOR:
        _xor_apply(buf, key)
    else:
        raise ValueError(f"unknown cipher_id {cipher_id}")
    return bytes(buf)


def gen_key_nonce() -> tuple[bytes, bytes]:
    """Random 32-byte key and 16-byte nonce block (12-byte nonce + zero counter)."""
    key = os.urandom(32)
    nonce16 = os.urandom(12) + b"\x00\x00\x00\x00"
    return key, nonce16
