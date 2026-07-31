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


# ---- decinfo whitening (at-rest obfuscation) --------------------------------------
# The 128-byte decinfo record is XOR-masked with a ChaCha20 keystream whose KEY is a
# checksum over the stub's own code bytes (the span blob[decinfo_off - WHITEN_SPAN:decinfo_off]). This
# MUST match stub/stub_cipher.h (sopk_whiten_key + SOPK_WHITEN_NONCE) byte for byte: the
# desktop side whitens, the injected stub recomputes the same key from its own code and
# de-whitens. See stub/decinfo.h for the rationale.
_MASK64 = 0xFFFFFFFFFFFFFFFF

# Number of stub bytes immediately before g_decinfo that the self-checksum covers.
# Mirror of SOPK_WHITEN_SPAN in stub/decinfo.h.
WHITEN_SPAN = 1024

# Fixed 16-byte ChaCha nonce block for whitening (mirror of SOPK_WHITEN_NONCE).
WHITEN_NONCE = bytes([
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15,
    0xf1, 0x35, 0x7a, 0xed, 0x03, 0x9d, 0x2c, 0x1a,
])


def whiten_key(span: bytes) -> bytes:
    """32-byte whitening key = FNV-1a-64 over `span`, splitmix64-expanded to 32 bytes so
    every output byte depends on every input byte (mirror of C sopk_whiten_key)."""
    h = 0xcbf29ce484222325                       # FNV-1a-64 offset basis
    for b in span:
        h = ((h ^ b) * 0x00000100000001b3) & _MASK64   # FNV prime
    out = bytearray()
    s = h
    for _ in range(4):                           # splitmix64 -> 32 bytes
        s = (s + 0x9e3779b97f4a7c15) & _MASK64
        z = s
        z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & _MASK64
        z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & _MASK64
        z = z ^ (z >> 31)
        out += struct.pack("<Q", z & _MASK64)
    return bytes(out)


def whiten(record: bytes, span: bytes) -> bytes:
    """XOR-mask (or unmask — it is its own inverse) the packed decinfo `record` with the
    ChaCha20 keystream keyed by whiten_key(span)."""
    return apply_cipher(CIPHER_CHACHA20, record, whiten_key(span), WHITEN_NONCE)
