/*
 * decinfo.h — the binary contract between the desktop injector (Python) and the
 * injected runtime stub (this C code). Both sides MUST agree on this layout byte
 * for byte. Keep it packed, little-endian, and fixed-size.
 *
 * The struct is emitted into the stub blob (section .sopk_info) with `magic`
 * pre-set. After the injector appends the stub blob to the target .so, it locates
 * this struct by scanning for `magic` and overwrites the data fields (deltas, key,
 * nonce, sizes). The stub reads it PC-relatively at runtime — see stub.c.
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
#define SOPK_VERSION 1u

/* cipher_id values */
#define SOPK_CIPHER_XOR      0u
#define SOPK_CIPHER_CHACHA20 1u

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
