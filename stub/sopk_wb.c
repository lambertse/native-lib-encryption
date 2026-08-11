/*
 * sopk_wb.c — REFERENCE source for the SHARED white-box provider used by
 * sopack's
 * `--cipher wbaes` mode. Requires whitebox-cryptography >= 3.0.0. One of these
 * ships per ABI (libsopk_wb.so); every thin per-target helper DT_NEEDEDs it.
 * See stub/sopk_wb.h for the split and why it is shaped this way, and
 * stub/sopk_rt.h for the region layouts.
 *
 * THE BUILD COMMAND AND ITS RATIONALE LIVE IN docs/wbaes-verification.md PHASE
 * 4 (step 4a). Not repeated here, because two copies drift. In outline: clang++
 * (not clang — libwbcrypto.a is C++) with a static libc++, `-x c` for this
 * file, --exclude-libs,ALL so the wbc_* symbols are not re-exported,
 * --no-undefined so a pre-3.0.0 archive fails HERE rather than on device, and
 * -Wl,-soname,libsopk_wb.so.
 *
 * -Wl,-soname IS LOAD-BEARING, not tidiness. The thin helper's DT_NEEDED string
 * is whatever the linker recorded as this file's DT_SONAME. Without an explicit
 * -soname, lld records the PATH it was handed
 * (".../sopack/stubs/sopk_wb_arm64-v8a.so") and the resulting APK cannot load.
 * The packer asserts DT_SONAME == libsopk_wb.so and refuses otherwise, and it
 * must never rename this artifact (unlike the per-target helpers, which it does
 * rename).
 *
 * NO CONSTRUCTOR. Everything happens lazily inside sopk_wb_k, so there is no
 * question about whether this object's ctor ran before anything needed it. The
 * thin helpers' ctors are the only triggers, and they stay 1:1 with their
 * targets.
 *
 * NEVER ABORTS. It returns SOPK_WB_ERR_* and records the same value in
 * sopk_wb_fail_code for the tombstone. The thin helper owns fail-closed
 * behaviour, so a failure is attributed to the step that failed rather than to
 * this shared object.
 */
#include <link.h> /* dl_iterate_phdr, ElfW */
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "wbcrypto.h" /* wbc_blob_kdf_tier / wbc_open / wbc_unwrap_key / ... (>= 3.0.0) */

#include "sopk_rt.h" /* sopk_wb_region, magics, markers, key sizes */
#include "sopk_wb.h" /* our own exported contract */
#include "stub_cipher.h" /* sopk_whiten_key / sopk_chacha20_apply / SOPK_WHITEN_NONCE */

/* Same contract as the thin helper's: fail the BUILD rather than emit a
 * wrong-length unwrap. */
_Static_assert(SOPK_RT_WRAPPED_KEY_BYTES == WBC_WRAPPED_KEY_BYTES,
               "sopk_rt_region.wrapped must match WBC_WRAPPED_KEY_BYTES");
_Static_assert(SOPK_RT_SESSION_KEY_BYTES == WBC_SESSION_KEY_BYTES,
               "SOPK_RT_SESSION_KEY_BYTES must match WBC_SESSION_KEY_BYTES");
/* provision.py's blob-header gate hardcodes tier 0 == light; make a renumbering
 * a build error. */
_Static_assert(
    (int)WBC_KDF_NONE == 0 && (int)WBC_KDF_LOW == 1 && (int)WBC_KDF_HIGH == 2,
    "wbc_kdf_tier numbering changed — provision.py assumes WBC_KDF_NONE == 0");
_Static_assert(SOPK_WB_ABI == SOPK_RT_REGION_VERSION,
               "SOPK_WB_ABI must track SOPK_RT_REGION_VERSION");

/* Retained build marker — see the note in sopk_rt.h. Must stay in an SHF_ALLOC
 * section: the packer strips every non-ALLOC section and its guard is a
 * byte-scan for these bytes. */
#if defined(__has_attribute)
#if __has_attribute(retain)
#define SOPK_WB_RETAIN __attribute__((retain))
#endif
#endif
#ifndef SOPK_WB_RETAIN
#define SOPK_WB_RETAIN
#endif
__attribute__((used)) SOPK_WB_RETAIN static const uint8_t
    sopk_wb_build_marker[SOPK_WB_BUILD_MARKER_LEN] = SOPK_WB_BUILD_MARKER_BYTES;

#ifdef SOPK_RT_LOG
#include <android/log.h>
#define SOPK_WB_LOG(...)                                                       \
  __android_log_print(ANDROID_LOG_INFO, "sopk_wb", __VA_ARGS__)
#else
#define SOPK_WB_LOG(...) ((void)0)
#endif

/* Readable in a tombstone even in a stripped, non-logging build. */
static volatile unsigned int sopk_wb_fail_code;

static int wb_fail(int code) {
  sopk_wb_fail_code = (unsigned int)code;
  return code;
}

#define SOPK_WB_MAX_PASS 256u /* mirrors SOPK_MAX_PASS in sopk_rt.c */

/* ---- locate our own appended provider region
 * ----------------------------------------- */
/* Same self-identification trick as the thin helper: find the module whose
 * PT_LOADs contain one of our own code addresses, then pick its read-only
 * PT_LOAD starting with our magic. The two magics differ ('SRTW' here, 'SRTT'
 * there), so neither scanner can pick up the other's region even though both
 * walk their own phdrs the same way. */
struct wb_self_scan {
  uintptr_t selfaddr;
  const uint8_t *region;
  size_t size;
};

static int wb_self_cb(struct dl_phdr_info *info, size_t sz, void *data) {
  (void)sz;
  struct wb_self_scan *s = (struct wb_self_scan *)data;
  ElfW(Addr) base = info->dlpi_addr;

  int is_self = 0;
  for (int i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
    if (ph->p_type != PT_LOAD)
      continue;
    uintptr_t lo = (uintptr_t)base + ph->p_vaddr;
    if (s->selfaddr >= lo && s->selfaddr < lo + ph->p_memsz) {
      is_self = 1;
      break;
    }
  }
  if (!is_self)
    return 0;

  for (int i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
    if (ph->p_type != PT_LOAD)
      continue;
    if (ph->p_flags & (PF_W | PF_X))
      continue; /* region is R-only */
    if (ph->p_memsz < SOPK_WB_REGION_HDR_SIZE)
      continue;
    const uint8_t *p = (const uint8_t *)((uintptr_t)base + ph->p_vaddr);
    const sopk_wb_region *r = (const sopk_wb_region *)p;
    if (r->magic == SOPK_WB_REGION_MAGIC &&
        r->version == SOPK_RT_REGION_VERSION) {
      s->region = p;
      s->size = (size_t)ph->p_memsz; /* bounds the variable-length tail */
      return 1;
    }
  }
  return 1; /* found self but no region -> caller reports SOPK_WB_ERR_REGION */
}

/* ---- the one export
 * ------------------------------------------------------------------ */
__attribute__((visibility("default"))) int
sopk_wb_k(unsigned abi, const uint8_t *wrapped, size_t wrapped_len, uint8_t *sk,
          size_t sk_len) {
  /* Serialise the whole call. There is no shared state to protect — but
   * storage::Unseal calls sodium_init(), whose concurrency contract is not
   * "safe to call concurrently", and two targets can be dlopen'd from different
   * threads. bionic's loader lock happens to serialise constructors today; do
   * not rely on it. */
  static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

  if (!wrapped || !sk)
    return wb_fail(SOPK_WB_ERR_ARG);
  if (wrapped_len != SOPK_RT_WRAPPED_KEY_BYTES ||
      sk_len != SOPK_RT_SESSION_KEY_BYTES)
    return wb_fail(SOPK_WB_ERR_ARG);
  /* A mismatched pair is caught HERE, as a clean first-call error, rather than
   * by producing a plausible-looking wrong session key and SIGILLing inside the
   * target later. */
  if (abi != SOPK_WB_ABI) {
    SOPK_WB_LOG("abi mismatch: helper %u, provider %u — rebuild BOTH skeletons",
                abi, (unsigned)SOPK_WB_ABI);
    return wb_fail(SOPK_WB_ERR_ABI);
  }

  pthread_mutex_lock(&lock);
  int rc = SOPK_WB_OK;

  struct wb_self_scan ss = {(uintptr_t)(void *)&sopk_wb_k, NULL, 0};
  dl_iterate_phdr(wb_self_cb, &ss);
  if (!ss.region) {
    rc = wb_fail(SOPK_WB_ERR_REGION);
    goto out;
  }

  const sopk_wb_region *r = (const sopk_wb_region *)ss.region;
  const uint8_t *tail = ss.region + SOPK_WB_REGION_HDR_SIZE;
  const uint8_t *wpass = tail;
  const uint8_t *blob = wpass + r->pass_len;
  uint32_t blob_len = r->blob_len;
  uint16_t pass_len = r->pass_len;

  /* blob_len >= WHITEN_SPAN because the whitening key is derived from the
   * blob's first SOPK_WHITEN_SPAN bytes; a shorter blob would read past it. */
  if (blob_len < SOPK_WHITEN_SPAN || pass_len == 0 ||
      pass_len >= SOPK_WB_MAX_PASS) {
    rc = wb_fail(SOPK_WB_ERR_FIELDS);
    goto out;
  }
  if ((size_t)SOPK_WB_REGION_HDR_SIZE + pass_len + blob_len > ss.size) {
    rc = wb_fail(SOPK_WB_ERR_TAIL);
    goto out;
  }

  /* De-whiten the passphrase. Key comes from the blob's own first bytes, so
   * nothing is baked in — and it is why wpass and blob must live in the same
   * artifact (see sopk_rt.h). */
  uint8_t wkey[32];
  char pass[SOPK_WB_MAX_PASS];
  sopk_whiten_key(blob, SOPK_WHITEN_SPAN, wkey);
  memcpy(pass, wpass, pass_len);
  sopk_chacha20_apply((uint8_t *)pass, pass_len, wkey, SOPK_WHITEN_NONCE);
  pass[pass_len] = '\0';
  memset(wkey, 0, sizeof(wkey));

  /* Read the tier before opening. Also the 3.0.0 version tripwire: wbc_kdf_tier
   * is an unknown type against a pre-3.0.0 wbcrypto.h (compile error), and
   * wbc_blob_kdf_tier is undefined against a pre-3.0.0 archive (--no-undefined
   * link error, and the packer's undefined-wbc_* guard after that). Not
   * value-gated: the host already asserted tier == light on this exact blob,
   * and the field is inside the seal's AEAD associated data so it cannot be
   * tampered. */
  wbc_kdf_tier tier = WBC_KDF_HIGH;
  wbc_status st = wbc_blob_kdf_tier(blob, blob_len, &tier);
  if (st != WBC_OK) {
    memset(pass, 0, sizeof(pass));
    SOPK_WB_LOG("wbc_blob_kdf_tier failed (%d)", (int)st);
    rc = wb_fail(SOPK_WB_ERR_TIER);
    goto out;
  }
  SOPK_WB_LOG("blob kdf tier = %d (0 = light/HKDF), blob=%u", (int)tier,
              blob_len);

  wbc_ctx *ctx = NULL;
  st = wbc_open(blob, blob_len, pass, &ctx);
  memset(pass, 0, sizeof(pass)); /* wipe ASAP */
  if (st != WBC_OK || !ctx) {
    SOPK_WB_LOG("wbc_open failed (%d)", (int)st);
    rc = wb_fail(SOPK_WB_ERR_OPEN);
    goto out;
  }

  /* The ONLY white-box work: two blocks, independent of .text size. Then close
   * immediately — the ctx holds a ~400 KB VM data image, and keeping it is a
   * recorded deferred change, not an oversight
   * (docs/potential-improvements.md). */
  st = wbc_unwrap_key(ctx, wrapped, sk);
  wbc_close(ctx);
  if (st != WBC_OK) {
    wbc_wipe(sk, sk_len); /* wipe before returning, not after */
    SOPK_WB_LOG("wbc_unwrap_key failed (%d)", (int)st);
    rc = wb_fail(SOPK_WB_ERR_UNWRAP);
    goto out;
  }

out:
  pthread_mutex_unlock(&lock);
  return rc;
}
