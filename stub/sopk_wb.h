/*
 * sopk_wb.h - the ONE symbol the shared white-box provider exports, and its
 * contract.
 *
 * `--cipher wbaes` ships two hand-built artifacts per ABI:
 *
 *   libsopk_rt_<target>.so   one THIN helper per protected library. DT_NEEDED
 * of its target, so bionic runs its ctor before the target's own init. Carries
 * the per-target region ('SRTT'). Does NOT link the white-box at all.
 *   libsopk_wb.so            ONE shared provider per ABI. DT_NEEDED of every
 * thin helper. Carries the sealed blob + whitened passphrase ('SRTW') and links
 *                            libwbcrypto.a. Exports exactly sopk_wb_k, below.
 *
 * WHY THE SPLIT KEEPS THE TRIGGER 1:1 WITH THE TARGET. bionic runs a shared
 * object's constructors exactly ONCE. A single helper shared by N targets would
 * therefore only decrypt the libraries already mapped when the FIRST target
 * loads; a library dlopen'd later (Flutter's libapp.so) would never be
 * decrypted, and the helper fails closed. Keeping one thin helper per target is
 * the only thing that makes "is my target mapped when my ctor runs?"
 * answerable. The provider is shared, but it is not a trigger - it has NO
 * constructor and does all its work lazily inside the call below, so there is
 * no ordering question about it at all.
 *
 * See docs/technical/WBAES.md Phase 4 for the two build commands. The
 * provider's is the one that needs clang++, -static-libstdc++,
 * --exclude-libs,ALL and -Wl,-soname.
 */
#ifndef SOPK_WB_H
#define SOPK_WB_H

#include <stddef.h>
#include <stdint.h>

/* Must equal SOPK_RT_REGION_VERSION. Passed on every call so a mismatched
 * thin-helper / provider PAIR is a controlled first-call failure instead of a
 * wrong-length unwrap. */
#define SOPK_WB_ABI 3u

/* Provider reason codes. 0 == success. The thin helper folds a non-zero value
 * into its own fail code as (10 + reason), i.e. the 10..19 band - see
 * sopk_rt.c. */
enum {
  SOPK_WB_OK = 0,
  SOPK_WB_ERR_ARG = 1, /* NULL pointer or wrong buffer length                */
  SOPK_WB_ERR_ABI = 2, /* abi != SOPK_WB_ABI: mismatched artifact pair       */
  SOPK_WB_ERR_REGION =
      3, /* no 'SRTW' region found in our own program headers  */
  SOPK_WB_ERR_FIELDS = 4, /* region header fields fail sanity checks */
  SOPK_WB_ERR_TAIL = 5, /* declared tail runs past the mapped region          */
  SOPK_WB_ERR_TIER = 6, /* wbc_blob_kdf_tier failed: bad/foreign blob format  */
  SOPK_WB_ERR_OPEN = 7, /* wbc_open failed (wrong passphrase or tampered blob)*/
  SOPK_WB_ERR_UNWRAP = 8, /* wbc_unwrap_key failed */
};

/*
 * Unwrap one target's 32-byte session key through the shared white-box.
 *
 * `abi`         must be SOPK_WB_ABI.
 * `wrapped`     the target region's 48-byte wrapped key (16-byte IV || 32-byte
 * ciphertext). `wrapped_len` must be 48. Explicit so a future layout change is
 * a clean runtime error rather than reading past the caller's buffer. `sk`
 * receives the 32-byte session key. `sk_len` must be 32.
 *
 * STATELESS BY DESIGN: every call does de-whiten passphrase -> wbc_open ->
 * wbc_unwrap_key -> wbc_close. Nothing is cached. That costs ~1 ms per call at
 * the `light` KDF tier and buys two things: the ~400 KB white-box VM image is
 * resident for microseconds instead of the whole process lifetime, and there is
 * no shared wbc_ctx - which matters because upstream documents wbc_ctx as NOT
 * thread-safe. Caching it is a recorded, deliberately-deferred change; see
 * docs/technical/IMPROVEMENTS.md before "optimising" this.
 *
 * NEVER ABORTS and never logs unless built with -DSOPK_RT_LOG. Failing closed
 * is the CALLER's job: this is a library, and the thin helper owns the abort so
 * the tombstone names the step.
 */
int sopk_wb_k(unsigned abi, const uint8_t *wrapped, size_t wrapped_len,
              uint8_t *sk, size_t sk_len);

#endif /* SOPK_WB_H */
