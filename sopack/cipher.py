"""Stream ciphers for encrypting .so `.text`. MUST match stub/stub_cipher.h byte for
byte, because the desktop side encrypts and the injected stub decrypts with the same
keystream.

Pure-Python (no external crypto dependency) so the tool has a small footprint. A `.text`
section is NOT always small, though — a Flutter `libapp.so` runs to several MB, and the
pure-Python ChaCha20 manages only ~0.6 MB/s — so both stream ciphers here take a system
`openssl` fast path when one is available, falling back to Python when it is not. The
fast paths are byte-identical by construction and pinned by KATs in tests/test_cipher.py.
"""
from __future__ import annotations

import os
import shutil
import struct
import subprocess

CIPHER_XOR = 0
CIPHER_CHACHA20 = 1
CIPHER_WBAES = 2   # white-box AES-128-CTR: host encrypts, on-device white-box decrypts

CIPHER_IDS = {"xor": CIPHER_XOR, "chacha20": CIPHER_CHACHA20, "wbaes": CIPHER_WBAES}

# wbcrypto 2.0.0 key-wrap sizes. Must equal WBC_SESSION_KEY_BYTES / WBC_WRAPPED_KEY_BYTES
# in the SDK header; stub/sopk_rt.h mirrors them and stub/sopk_rt.c static_asserts them.
# A session key is also exactly a ChaCha20 key, which is why the bulk needs no second key.
SESSION_KEY_BYTES = 32
WRAPPED_KEY_BYTES = 16 + SESSION_KEY_BYTES   # wrap IV || CTR-wrapped session key


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


# Below this size the subprocess round-trip costs more than the pure-Python loop. It also
# keeps the small, hot callers (decinfo whitening, whiten_pass) off the fast path entirely.
_OPENSSL_MIN = 1 << 16

# Bytes of every openssl result that are re-checked against the pure-Python reference.
_FASTPATH_CHECK = 128


def _fastpath_ok(out: bytes, data: bytes, reference) -> bool:
    """Accept an openssl result only if its length matches AND a prefix matches the
    pure-Python reference. `reference(n)` returns the first n bytes we would have produced.

    Checking the length alone is NOT enough, and the gap is a silent one. A build whose
    16-byte IV convention differs from ours — e.g. ChaCha20's original counter(8)||nonce(8)
    layout rather than openssl's counter(4, LE)||nonce(12) — accepts the same arguments and
    returns the SAME LENGTH with wrong bytes. Nothing downstream would notice:
    `_self_verify_wbaes` only checks the file holds the ciphertext the packer produced, not
    that the packer produced the right ciphertext, so the corruption would ship and surface
    as a crashing app on device. This matters in practice because the pack host's `openssl`
    is not one implementation (macOS ships LibreSSL, Linux ships OpenSSL 3.x).

    Cost is one keystream block per call, against a multi-MB payload — free in context."""
    if len(out) != len(data):
        return False
    n = min(len(data), _FASTPATH_CHECK)
    return out[:n] == reference(n)


def _chacha20_openssl(data: bytes, key: bytes, nonce16: bytes) -> bytes | None:
    """ChaCha20 via the system `openssl`, or None if it is unavailable or disagrees with us.

    openssl's `-chacha20` takes a 16-byte IV laid out as counter(4, little-endian) followed
    by nonce(12); ours is nonce(12) followed by counter(4, LE), so the halves swap."""
    try:
        exe = shutil.which("openssl")
        if not exe:
            return None
        ossl_iv = nonce16[12:16] + nonce16[0:12]
        p = subprocess.run(
            [exe, "enc", "-chacha20", "-K", key.hex(), "-iv", ossl_iv.hex()],
            input=data, capture_output=True, check=True,
        )

        def reference(n: int) -> bytes:
            probe = bytearray(data[:n])
            _chacha20_apply(probe, key, nonce16)
            return bytes(probe)

        return p.stdout if _fastpath_ok(p.stdout, data, reference) else None
    except Exception:
        return None


def apply_cipher(cipher_id: int, data: bytes, key: bytes, nonce16: bytes) -> bytes:
    """Encrypt/decrypt (identical for a stream cipher). Length-preserving."""
    if cipher_id == CIPHER_CHACHA20:
        if len(data) >= _OPENSSL_MIN:
            fast = _chacha20_openssl(data, key, nonce16)
            if fast is not None:
                return fast
        buf = bytearray(data)
        _chacha20_apply(buf, key, nonce16)
    elif cipher_id == CIPHER_XOR:
        buf = bytearray(data)
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


# ---- AES-128-CTR: the `wbaes` KEY-WRAP primitive ----------------------------------
# NOT a bulk cipher any more. wbcrypto 2.0.0 deleted wbc_crypt_ctr/wbc_encrypt_ecb, so the
# white-box no longer touches `.text`; it only wraps a 32-byte session key. This function
# is how the PACK HOST produces that wrap without needing a new host tool.
#
# The white-box VM in libwbcrypto is a bit-exact standard AES-128 (external encodings =
# identity; verified against FIPS-197 69c4e0d8...), and wbc_wrap_key is plain CTR over the
# session key under the sealed key (src/sdk/wbcrypto.cpp:CtrSessionKey). Since the host
# still holds that key when it seals it, the host can compute the wrap here:
#
#     wrapped = wrap_iv || aes128_ctr(session_key, kek, wrap_iv)
#
# Counter convention MUST match CtrSessionKey: the full 16-byte IV is the initial counter,
# incremented as a 128-bit BIG-ENDIAN integer; keystream block = E(counter); a partial final
# block is truncated. Verified byte-exact against the real 2.0.0 wbc_unwrap_key — see the
# KAT in tests/test_cipher.py.
AES_BLOCK = 16

_AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)

# Round constants for AES-128 key expansion (10 rounds).
_AES_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _aes_xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _aes128_key_schedule(key: bytes) -> list:
    """Expand a 16-byte key into 11 round keys (each a list of 16 bytes)."""
    assert len(key) == 16
    words = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(words[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]                                  # RotWord
            t = [_AES_SBOX[b] for b in t]                      # SubWord
            t[0] ^= _AES_RCON[i // 4 - 1]
        words.append([words[i - 4][j] ^ t[j] for j in range(4)])
    return [sum(words[r * 4:r * 4 + 4], []) for r in range(11)]


def _aes128_encrypt_block(block: bytes, round_keys: list) -> bytes:
    s = [block[i] ^ round_keys[0][i] for i in range(16)]      # AddRoundKey (initial)
    for rnd in range(1, 11):
        s = [_AES_SBOX[b] for b in s]                         # SubBytes
        # ShiftRows (column-major state: byte at row r, col c is s[c*4 + r]).
        s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3],
             s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]
        if rnd != 10:                                         # MixColumns
            for c in range(4):
                col = s[c * 4:c * 4 + 4]
                t = col[0] ^ col[1] ^ col[2] ^ col[3]
                s[c * 4 + 0] = col[0] ^ t ^ _aes_xtime(col[0] ^ col[1])
                s[c * 4 + 1] = col[1] ^ t ^ _aes_xtime(col[1] ^ col[2])
                s[c * 4 + 2] = col[2] ^ t ^ _aes_xtime(col[2] ^ col[3])
                s[c * 4 + 3] = col[3] ^ t ^ _aes_xtime(col[3] ^ col[0])
        s = [s[i] ^ round_keys[rnd][i] for i in range(16)]   # AddRoundKey
    return bytes(s)


def _aes128_ctr_py(data: bytes, key: bytes, iv: bytes) -> bytes:
    rk = _aes128_key_schedule(key)
    ctr = bytearray(iv)
    out = bytearray(len(data))
    off = 0
    while off < len(data):
        ks = _aes128_encrypt_block(bytes(ctr), rk)
        n = min(AES_BLOCK, len(data) - off)
        for i in range(n):
            out[off + i] = data[off + i] ^ ks[i]
        off += n
        for i in range(15, -1, -1):                          # 128-bit big-endian ++
            ctr[i] = (ctr[i] + 1) & 0xFF
            if ctr[i]:
                break
    return bytes(out)


def aes128_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Standard AES-128-CTR (encrypt == decrypt). Matches the white-box's own CTR, so
    `iv + aes128_ctr(sk, kek, iv)` equals what `wbc_wrap_key(ctx, sk, ...)` would emit.
    Uses the system `openssl` when available, else a pure-Python path."""
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("aes128_ctr requires 16-byte key and iv")
    if not data:
        return b""
    try:
        exe = shutil.which("openssl")
        if exe:
            p = subprocess.run(
                [exe, "enc", "-aes-128-ctr", "-K", key.hex(), "-iv", iv.hex()],
                input=data, capture_output=True, check=True,
            )
            # Same prefix self-check as the ChaCha20 path. AES-CTR's `-iv` semantics are
            # unambiguous so a divergence is unlikely, but the structural gap is identical
            # and closing it costs one block.
            if _fastpath_ok(p.stdout, data, lambda n: _aes128_ctr_py(data[:n], key, iv)):
                return p.stdout
    except Exception:
        pass                                                 # fall back to pure-Python
    return _aes128_ctr_py(data, key, iv)


def gen_wbaes_params() -> tuple[bytes, bytes, bytes, bytes]:
    """Fresh per-library key material for `--cipher wbaes` (key wrapping):

        kek      — 16-byte AES-128 long-term key; sealed into the white-box, then discarded
        sk       — 32-byte session key; drives the ChaCha20 over `.text`, then discarded
        wrap_iv  — 16-byte CTR IV for the wrap (ships in the clear ahead of the wrapped key)
        nonce16  — ChaCha20 nonce block: 12-byte nonce + zero counter (see _chacha20_apply)
    """
    return (os.urandom(16), os.urandom(SESSION_KEY_BYTES), os.urandom(16),
            os.urandom(12) + b"\x00\x00\x00\x00")


def whiten_pass(passphrase: bytes, blob: bytes) -> bytes:
    """Obfuscate (or de-obfuscate — self-inverse) the embedded passphrase with a ChaCha20
    keystream keyed off the sealed blob's own first `WHITEN_SPAN` bytes. Both the packer and
    the on-device helper have the blob, so no baked constant or code-span anchor is needed.
    Reuses whiten_key + WHITEN_NONCE; the helper (`stub/sopk_rt.c`) mirrors this exactly."""
    return apply_cipher(CIPHER_CHACHA20, passphrase, whiten_key(blob[:WHITEN_SPAN]), WHITEN_NONCE)
