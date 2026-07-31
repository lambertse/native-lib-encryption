/*
 * decinfo.h — the binary contract between the desktop injector (Python) and the
 * injected runtime stub (this C code). Both sides MUST agree on this layout byte
 * for byte. Keep it packed, little-endian, and fixed-size.
 *
 * The struct is emitted into the stub blob (section .sopk_info) with `magic`
 * pre-set. After the injector appends the stub blob to the target .so, it overwrites
 * the data fields (deltas, key, nonce, sizes) at the KNOWN blob offset (no magic scan)
 * and then WHITENS the whole 128-byte record — see the whitening note below. The stub
 * reads it PC-relatively at runtime — see stub.c.
 *
 * At-rest whitening (v2, anti-static-analysis). The shipped record is XOR-masked with a
 * ChaCha20 keystream whose key is a checksum the stub computes over ITS OWN code bytes
 * at load (the SOPK_WHITEN_SPAN bytes immediately before g_decinfo; mirrored in sopack/cipher.py ⇄
 * stub/stub_cipher.h). Consequences: (1) the constant `magic` never appears in the
 * shipped file, so the old "grep SOPK, read the 128-byte struct, lift the key" attack
 * finds nothing; (2) key/nonce/sizes are noise until an analyst reproduces the
 * checksum+keystream derivation by reversing the stub. `magic`/`version` reappear only
 * after a correct de-whiten, so they double as an integrity sentinel: a tampered stub
 * (or an unpatched blob) de-whitens to garbage, the magic check fails, and the stub
 * fails open (chains the original init) instead of running still-encrypted code.
 * This is obfuscation, not cryptographic protection — the stub ships identical in every
 * packed app, so reversing it once yields a universal offline unpacker for that version.
 *
 * Key trick: we never need the host library's load bias. Everything the stub must
 * reach (.text, original init) is expressed as a byte delta FROM THE ADDRESS OF
 * THIS STRUCT, which the stub already knows at runtime (the compiler references it
 * PC-relatively). So:  target_runtime = (uintptr)&g_decinfo + delta.
 */
#ifndef SOPK_DECINFO_H
#define SOPK_DECINFO_H

#include <stdint.h>

#define SOPK_MAGIC   0x4B504F53u   /* "SOPK" little-endian */
#define SOPK_VERSION 2u            /* v2: record is whitened at rest (see below) */

/* cipher_id values */
#define SOPK_CIPHER_XOR      0u
#define SOPK_CIPHER_CHACHA20 1u

/* Whitening span: number of stub code/rodata bytes IMMEDIATELY BEFORE g_decinfo that the
 * self-checksum (which derives the de-whitening key) covers. Anchored on &g_decinfo only
 * (a data symbol the compiler reaches PC-relatively; a function symbol like &sopk_entry
 * emits an unresolved arm64 relocation). Every stub blob is far larger than this, and the
 * injector never rewrites these bytes. MUST match WHITEN_SPAN in sopack/cipher.py. */
#define SOPK_WHITEN_SPAN 1024u

/* flags bits */
#define SOPK_FLAG_CHAIN_INIT  (1u << 0)  /* delta_init valid: tail-call original init */
#define SOPK_FLAG_NEED_ICACHE (1u << 1)  /* flush I-cache after decrypt (arm) */
#define SOPK_FLAG_LOG         (1u << 2)  /* emit a logcat confirmation on success */

typedef struct __attribute__((packed)) sopk_decinfo {
    uint32_t magic;       /* SOPK_MAGIC */
    uint32_t version;     /* SOPK_VERSION */
    uint32_t cipher_id;   /* SOPK_CIPHER_* */
    uint32_t flags;       /* SOPK_FLAG_* */
    int64_t  delta_text;  /* text_rva  - decinfo_rva */
    uint64_t text_size;   /* exact .text byte length (sub-range to decrypt) */
    int64_t  delta_init;  /* orig_init_rva - decinfo_rva (only if CHAIN_INIT) */
    uint8_t  key[32];     /* cipher key */
    uint8_t  nonce[16];   /* cipher nonce / counter seed */
    uint8_t  reserved[40];/* pad to 128 bytes; room for future fields */
} sopk_decinfo;

_Static_assert(sizeof(struct sopk_decinfo) == 128, "decinfo must be 128 bytes");

#endif /* SOPK_DECINFO_H */
