/*
 * stub_cipher.h - freestanding decrypt routines used by the stub. Must
 * byte-for-byte match sopack/cipher.py on the desktop side.
 *
 *   XOR      : keystream = repeating key[0..31]  (debug / learning only)
 *   ChaCha20 : RFC 8439, 32-byte key, 96-bit nonce, 32-bit block counter.
 *              decinfo.nonce layout: bytes[0..11]=nonce, bytes[12..15]=initial
 *              counter (little-endian, normally 0).
 *
 * Decryption of a stream cipher == encryption (XOR with keystream), so the same
 * code both encrypts (desktop) and decrypts (device).
 */
#ifndef SOPK_STUB_CIPHER_H
#define SOPK_STUB_CIPHER_H

#include "decinfo.h"
#include <stddef.h>
#include <stdint.h>

static inline void sopk_xor_apply(uint8_t *buf, size_t n,
                                  const uint8_t key[32]) {
  for (size_t i = 0; i < n; i++)
    buf[i] ^= key[i & 31];
}

/* ---- ChaCha20 (RFC 8439) ---- */
static inline uint32_t sopk_rotl32(uint32_t x, int c) {
  return (x << c) | (x >> (32 - c));
}
static inline uint32_t sopk_load32_le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

#define SOPK_QR(a, b, c, d)                                                    \
  a += b;                                                                      \
  d ^= a;                                                                      \
  d = sopk_rotl32(d, 16);                                                      \
  c += d;                                                                      \
  b ^= c;                                                                      \
  b = sopk_rotl32(b, 12);                                                      \
  a += b;                                                                      \
  d ^= a;                                                                      \
  d = sopk_rotl32(d, 8);                                                       \
  c += d;                                                                      \
  b ^= c;                                                                      \
  b = sopk_rotl32(b, 7)

static inline void sopk_chacha20_block(const uint32_t in[16], uint8_t out[64]) {
  uint32_t x[16];
  for (int i = 0; i < 16; i++)
    x[i] = in[i];
  for (int i = 0; i < 10; i++) { /* 20 rounds = 10 double-rounds */
    SOPK_QR(x[0], x[4], x[8], x[12]);
    SOPK_QR(x[1], x[5], x[9], x[13]);
    SOPK_QR(x[2], x[6], x[10], x[14]);
    SOPK_QR(x[3], x[7], x[11], x[15]);
    SOPK_QR(x[0], x[5], x[10], x[15]);
    SOPK_QR(x[1], x[6], x[11], x[12]);
    SOPK_QR(x[2], x[7], x[8], x[13]);
    SOPK_QR(x[3], x[4], x[9], x[14]);
  }
  for (int i = 0; i < 16; i++) {
    uint32_t v = x[i] + in[i];
    out[i * 4 + 0] = (uint8_t)(v);
    out[i * 4 + 1] = (uint8_t)(v >> 8);
    out[i * 4 + 2] = (uint8_t)(v >> 16);
    out[i * 4 + 3] = (uint8_t)(v >> 24);
  }
}

static inline void sopk_chacha20_apply(uint8_t *buf, size_t n,
                                       const uint8_t key[32],
                                       const uint8_t nonce16[16]) {
  uint32_t st[16];
  st[0] = 0x61707865;
  st[1] = 0x3320646e; /* "expand 32-byte k" */
  st[2] = 0x79622d32;
  st[3] = 0x6b206574;
  for (int i = 0; i < 8; i++)
    st[4 + i] = sopk_load32_le(key + i * 4);
  st[12] = sopk_load32_le(nonce16 + 12); /* initial block counter */
  st[13] = sopk_load32_le(nonce16 + 0);
  st[14] = sopk_load32_le(nonce16 + 4);
  st[15] = sopk_load32_le(nonce16 + 8);

  uint8_t ks[64];
  size_t off = 0;
  while (off < n) {
    sopk_chacha20_block(st, ks);
    size_t chunk = n - off < 64 ? n - off : 64;
    for (size_t i = 0; i < chunk; i++)
      buf[off + i] ^= ks[i];
    off += chunk;
    st[12]++; /* 32-bit block counter, wraps (RFC 8439: no carry into nonce) */
  }
}

/* Decrypt with explicit (non-volatile) key/nonce locals - the caller copies
 * them out of the volatile g_decinfo first so the compiler cannot constant-fold
 * the cipher. */
static inline void sopk_decrypt(uint8_t *buf, size_t n, uint32_t cipher_id,
                                const uint8_t key[32],
                                const uint8_t nonce[16]) {
  if (cipher_id == SOPK_CIPHER_CHACHA20)
    sopk_chacha20_apply(buf, n, key, nonce);
  else
    sopk_xor_apply(buf, n, key);
}

/* ---- decinfo whitening (at-rest obfuscation)
 * --------------------------------------- The 128-byte decinfo record is
 * XOR-masked with a ChaCha20 keystream whose KEY is a checksum over the stub's
 * own code bytes. Both the checksum (sopk_whiten_key) and the fixed nonce below
 * MUST match sopack/cipher.py byte for byte. De-whitening is just
 * sopk_chacha20_apply() over the 128 bytes with (whiten_key,
 * SOPK_WHITEN_NONCE).
 *
 * Checksum: FNV-1a-64 over the span, then splitmix64 expanded to 32 bytes so
 * every key byte depends on every span byte (tamper anywhere -> wrong key ->
 * garbage de-whiten). No new primitive on the wire - only this small mixing
 * function is added on both sides.
 */
static const uint8_t SOPK_WHITEN_NONCE[16] = {
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15,
    0xf1, 0x35, 0x7a, 0xed, 0x03, 0x9d, 0x2c, 0x1a,
};

static inline void sopk_whiten_key(const uint8_t *span, size_t n,
                                   uint8_t out[32]) {
  uint64_t h = 0xcbf29ce484222325ULL; /* FNV-1a-64 offset basis */
  for (size_t i = 0; i < n; i++)
    h = (h ^ (uint64_t)span[i]) * 0x00000100000001b3ULL; /* FNV prime */
  uint64_t s = h;
  for (int j = 0; j < 4; j++) { /* splitmix64 -> 32 bytes */
    s += 0x9e3779b97f4a7c15ULL;
    uint64_t z = s;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    z = z ^ (z >> 31);
    for (int k = 0; k < 8; k++)
      out[j * 8 + k] = (uint8_t)(z >> (8 * k));
  }
}

#endif /* SOPK_STUB_CIPHER_H */
