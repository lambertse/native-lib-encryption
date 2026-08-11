/*
 * sopk_rt.h - binary contract between the sopack packer (Python) and the
 * white-box runtime helper (`libsopk_rt_<target>.so`, built by the USER from
 * sopk_rt.c with the NDK + O-MVLL). Both sides MUST agree on this layout byte
 * for byte.
 *
 * This is the `--cipher wbaes` runtime model. Unlike the freestanding stub
 * (decinfo.h), the helper is a NORMAL Android .so that statically links the
 * white-box AES-128 VM (libwbcrypto.a). It is injected as a DT_NEEDED of the
 * target, so bionic runs its constructor BEFORE the target's own init; the ctor
 * decrypts the target's `.text` in place (mremap onto the original VA) and
 * returns.
 *
 * KEY WRAPPING (wbcrypto >= 3.0.0). The white-box is NOT used on the bulk data:
 * it unwraps a 32-byte session key in two blocks (payload-independent) and that
 * key drives sopack's own ChaCha20 over `.text`. The long-term AES-128 key is
 * still never reconstructed; only the session key exists in memory, and only
 * between the unwrap and the wipe. Why it is done this way, and why not the
 * SDK's own AEAD: docs/technical/ARCHITECTURE.md §11b-c.
 *
 * How the ctor finds its data: the packer appends ONE read-only PT_LOAD to the
 * helper whose bytes are a `sopk_rt_region` (below), starting with
 * SOPK_RT_REGION_MAGIC. The ctor walks its OWN program headers
 * (dl_iterate_phdr, self-identified by an in-range code-address test) and picks
 * the PT_LOAD that begins with the magic. No symbol is patched and no static
 * file offset is trusted - this survives LIEF re-basing the skeleton when the
 * region segment is appended.
 *
 * Security note (same ceiling as decinfo.h): this raises the static-analysis
 * cost. The long-term AES key is diffused into the white-box tables and never
 * reconstructed at runtime, so - unlike the freestanding stub - no portable key
 * can be lifted from the shipped bytes. What key wrapping gives up: the SESSION
 * key is an ordinary key in ordinary memory between the unwrap and the wipe, so
 * an attacker who can dump the process gets it without attacking the white-box
 * at all. The embedded passphrase is whitened (obfuscation-grade), and
 * plaintext `.text` still exists in an R-X mapping at runtime. Do not oversell
 * it.
 */
#ifndef SOPK_RT_H
#define SOPK_RT_H

#include <stdint.h>

/* Region magics/version. TWO kinds of region exist, deliberately with different
 * magics so each scanner refuses the other kind for free:
 *
 *   'S','R','T','T'  target region, in each thin per-target helper
 * (libsopk_rt_<target>.so) 'S','R','T','W'  provider region, in the ONE shared
 * libsopk_wb.so per ABI
 *
 * v3 split them. Up to v2 a single region carried BOTH the per-target fields
 * and the sealed blob + passphrase, so every helper shipped its own ~455 KB
 * blob; v3 moves the blob and the passphrase into the shared provider, leaving
 * each thin helper a few KB.
 *
 * NOTE FOR ANYONE EDITING THE TARGET HEADER: it is still 96 bytes and its
 * Python struct format is still textually "<IIQQ48s16sHHI" - pass_len/blob_len
 * were replaced by flags/reserved of the same widths. So a size or
 * format-string assertion will NOT catch v2/v3 drift. The magic change is what
 * does; keep the b"SRTT" and version-3 assertions in tests/test_rt_meta.py.
 *
 * v1 carried an AES-CTR iv and was decrypted by the now-deleted wbc_crypt_ctr.
 * Both ctors require an exact version match, so packer and skeletons ship as a
 * matched set - see the build-marker note below. */
#define SOPK_RT_REGION_MAGIC 0x54545253u /* 'SRTT' - target region   */
#define SOPK_WB_REGION_MAGIC 0x57545253u /* 'SRTW' - provider region */
#define SOPK_RT_REGION_VERSION 3u

/*
 * Target region - appended to each thin per-target helper. Fixed 96-byte header
 * + tail: soname[soname_len]  - the TARGET's soname (matched by basename via
 * dl_iterate_phdr) Packed little-endian; the packer (sopack/rt_meta.py) writes
 * it, this header parses it.
 */
typedef struct __attribute__((packed)) sopk_rt_region {
  uint32_t magic;   /* SOPK_RT_REGION_MAGIC ('SRTT')                          */
  uint32_t version; /* SOPK_RT_REGION_VERSION                                 */
  uint64_t text_rva;  /* target .text RVA (read AFTER add(seg) re-bases it)  */
  uint64_t text_size; /* exact .text byte length to decrypt */
  uint8_t
      wrapped[48]; /* wbc_wrap_key output: 16-byte IV || 32-byte wrapped key */
  uint8_t nonce16[16]; /* ChaCha20 nonce: [0:12]=nonce, [12:16]=counter (LE) */
  uint16_t soname_len; /* length of the target soname that follows (no NUL) */
  uint16_t flags; /* MBZ - reserved                                         */
  uint32_t reserved; /* MBZ - reserved (was blob_len before v3)               */
                     /* uint8_t soname[soname_len];                    */
} sopk_rt_region;

_Static_assert(sizeof(struct sopk_rt_region) == 96,
               "sopk_rt_region header must be 96 bytes");

#define SOPK_RT_REGION_HDR_SIZE 96u

/*
 * Provider region - appended to the ONE shared libsopk_wb.so per ABI. Fixed
 * 24-byte header
 * + tail:
 *     wpass[pass_len]   - whitened passphrase
 *     blob[blob_len]    - the sealed white-box blob (~455 KB at blob format v4)
 *
 * wpass and blob MUST stay in the same artifact: the whitening key is derived
 * from the blob's own first SOPK_WHITEN_SPAN bytes (see the whitening note
 * below), so splitting them across two .so files would make any provider/helper
 * version skew a silent wbc_open failure.
 */
typedef struct __attribute__((packed)) sopk_wb_region {
  uint32_t magic;   /* SOPK_WB_REGION_MAGIC ('SRTW')                          */
  uint32_t version; /* SOPK_RT_REGION_VERSION - one version for both kinds    */
  uint32_t blob_len; /* length of the sealed white-box blob in the tail */
  uint16_t pass_len; /* length of the whitened passphrase in the tail */
  uint16_t flags; /* MBZ - reserved                                          */
  uint32_t reserved0; /* MBZ - reserved */
  uint32_t reserved1; /* MBZ - reserved */
  /* uint8_t wpass[pass_len]; uint8_t blob[blob_len]; */
} sopk_wb_region;

_Static_assert(sizeof(struct sopk_wb_region) == 24,
               "sopk_wb_region header must be 24 bytes");

#define SOPK_WB_REGION_HDR_SIZE 24u

/* Session key length; must equal WBC_SESSION_KEY_BYTES and ChaCha20's key size.
 * The .c static_asserts it against the SDK header so a 2.x change is a build
 * error, not a silent wrong-length wrap. */
#define SOPK_RT_SESSION_KEY_BYTES 32u
/* Length of sopk_rt_region.wrapped; must equal WBC_WRAPPED_KEY_BYTES. */
#define SOPK_RT_WRAPPED_KEY_BYTES 48u

/*
 * Build marker. The skeleton is built by hand, outside this repo, so a stale
 * one is easy to leave in sopack/stubs/. A stale skeleton finds no region (the
 * version gate above fails) and now aborts - but the abort carries no
 * explanation, and the fix is a rebuild, not a debugging session. sopk_rt.c
 * therefore embeds these bytes in a retained variable and the packer
 * (elf_inject.py:_emit_helper) refuses a skeleton that lacks them, turning a
 * device-side crash into a pack-time error naming the remedy. Bump them on ANY
 * change to this layout or to the crypto flow, and mirror the change in
 * sopack/rt_meta.py:HELPER_BUILD_MARKER.
 *
 * The marker must live in an SHF_ALLOC section: the packer strips every
 * non-ALLOC section from the emitted helper, and its own guard is a byte-scan
 * for these bytes. `.rodata` (where a `static const` lands) is fine; do not
 * move it to a debug or note section.
 *
 * Deliberately opaque bytes rather than an ASCII string: the appended region's
 * 'SRTT' magic is already a fingerprint, and there is no reason to add a second
 * one that spells out the tool's name. See docs/technical/HARDENING.md on
 * string hygiene.
 *
 * There are TWO markers now, one per hand-built artifact, and they are
 * deliberately DIFFERENT values: with a single shared marker, "freshly built
 * thin helper + stale provider" would pass both guards. That mismatched pair is
 * the real failure mode once two artifacts must be rebuilt together, so each
 * guard names which file to rebuild.
 *
 * Bumped ONCE for both changes that landed together: the wbcrypto 3.0.0
 * migration (the ctor reads the blob's KDF tier via wbc_blob_kdf_tier, so any
 * pre-3.0.0 link must be redone) and the v3 region split. One rebuild satisfies
 * both, so one bump is correct.
 *
 * SUPERSEDED VALUES - never reuse either:
 *   1dc74b92a630e852  (published in a reverse-engineering report)
 *   61eb361771ab71e2  (pre-3.0.0 fail-closed ctor + region-tail bounds check +
 * checked mprotect)
 */
#define SOPK_RT_BUILD_MARKER_BYTES                                             \
  {0x96, 0x02, 0xc8, 0xdb, 0x07, 0x61, 0xc4, 0xa8}
#define SOPK_RT_BUILD_MARKER_LEN 8u

/* Same contract, for the shared provider (stub/sopk_wb.c -> libsopk_wb.so). */
#define SOPK_WB_BUILD_MARKER_BYTES                                             \
  {0xe6, 0xe9, 0x03, 0xbf, 0xea, 0x5a, 0xf3, 0x40}
#define SOPK_WB_BUILD_MARKER_LEN 8u

/*
 * Passphrase whitening (reuses the stub's existing primitives verbatim - see
 * stub/stub_cipher.h and sopack/cipher.py). The key is derived from the sealed
 * blob's own first SOPK_WHITEN_SPAN bytes, which both sides hold, so no baked
 * constant is needed: sopk_whiten_key(blob, SOPK_WHITEN_SPAN, wkey);
 *     sopk_chacha20_apply(wpass, pass_len, wkey, SOPK_WHITEN_NONCE);   //
 * self-inverse SOPK_WHITEN_SPAN / SOPK_WHITEN_NONCE come from decinfo.h /
 * stub_cipher.h.
 */

#endif /* SOPK_RT_H */
