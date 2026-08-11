/*
 * rt_roundtrip.c - host round-trip of the FULL `--cipher wbaes` contract, no
 * device needed. Driven by scripts/build_wbaes.sh (Phase 3 of
 * docs/technical/WBAES.md).
 *
 * Parses the packer's region with the real C struct, de-whitens the passphrase,
 * opens the sealed blob with the real wbcrypto >= 3.0.0, unwraps the session
 * key, and ChaCha20-decrypts with the same code the on-device helper uses. It
 * therefore fails if ANY of these has drifted:
 *
 *   sopack/rt_meta.py  <->  stub/sopk_rt.h    (region layout: wrong
 * magic/version/sizes) sopack/cipher.py   <->  stub/stub_cipher.h (whitening:
 * wbc_open rejects the passphrase) cipher.aes128_ctr  <->  wbc_wrap_key (the
 * wrap: unwrap yields a wrong session key) sopack/cipher.py   <->
 * stub/stub_cipher.h (ChaCha20: the plaintext compare fails) provision.py --kdf
 * light <-> wbc_blob_kdf_tier (the tier: asserted below, must be 0)
 *
 * usage: rt_roundtrip wbregion.bin region.bin cipher.bin plain.bin
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sopk_rt.h"
#include "stub_cipher.h"
#include "wbcrypto.h"

static double ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static unsigned char *slurp(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f) {
    perror(p);
    exit(1);
  }
  fseek(f, 0, SEEK_END);
  long l = ftell(f);
  fseek(f, 0, SEEK_SET);
  unsigned char *b = malloc(l);
  if (!b || fread(b, 1, l, f) != (size_t)l) {
    fprintf(stderr, "short read: %s\n", p);
    exit(1);
  }
  fclose(f);
  *n = l;
  return b;
}

int main(int argc, char **argv) {
  if (argc != 5) {
    fprintf(stderr, "usage: %s wbregion.bin region.bin cipher.bin plain.bin\n",
            argv[0]);
    return 2;
  }
  /* Since region v3 the metadata is SPLIT across the two shipped artifacts: the
   * provider region carries the one sealed blob + passphrase, each target
   * region carries only its own wrapped key. Parse both here, in the same order
   * the device does. */
  size_t wn, rn, cn, pn;
  unsigned char *wb = slurp(argv[1], &wn), *rb = slurp(argv[2], &rn);
  unsigned char *ct = slurp(argv[3], &cn), *pt = slurp(argv[4], &pn);

  const sopk_wb_region *w = (const sopk_wb_region *)wb;
  printf("wb region: %zu bytes, hdr=%u\n", wn, SOPK_WB_REGION_HDR_SIZE);
  if (w->magic != SOPK_WB_REGION_MAGIC) {
    printf("FAIL: bad provider magic 0x%08x (rt_meta.py <-> sopk_rt.h drift)\n",
           w->magic);
    return 1;
  }
  if (w->version != SOPK_RT_REGION_VERSION) {
    printf("FAIL: provider region version %u != %u - packer/build disagree\n",
           w->version, SOPK_RT_REGION_VERSION);
    return 1;
  }
  const uint8_t *wpass = wb + SOPK_WB_REGION_HDR_SIZE;
  const uint8_t *blob = wpass + w->pass_len;

  const sopk_rt_region *r = (const sopk_rt_region *)rb;
  printf("target region: %zu bytes, hdr=%u\n", rn, SOPK_RT_REGION_HDR_SIZE);
  if (r->magic != SOPK_RT_REGION_MAGIC) {
    printf("FAIL: bad target magic 0x%08x (rt_meta.py <-> sopk_rt.h drift)\n",
           r->magic);
    return 1;
  }
  if (r->version != SOPK_RT_REGION_VERSION) {
    printf("FAIL: target region version %u != %u - the packer and this build "
           "disagree\n",
           r->version, SOPK_RT_REGION_VERSION);
    return 1;
  }
  /* A target region must NOT carry a blob any more. Its whole tail is the
   * soname. */
  if (rn != (size_t)SOPK_RT_REGION_HDR_SIZE + r->soname_len) {
    printf("FAIL: target region is %zu bytes, expected %u + soname %u - it "
           "still carries "
           "a blob, i.e. a pre-v3 region\n",
           rn, SOPK_RT_REGION_HDR_SIZE, r->soname_len);
    return 1;
  }
  const char *soname = (const char *)(rb + SOPK_RT_REGION_HDR_SIZE);
  printf("  magic/version OK  target='%.*s'  text_size=%llu  blob=%u  "
         "pass_len=%u\n",
         (int)r->soname_len, soname, (unsigned long long)r->text_size,
         w->blob_len, w->pass_len);
  if (r->text_size != cn || cn != pn) {
    printf("FAIL: size mismatch (region %llu, cipher %zu, plain %zu)\n",
           (unsigned long long)r->text_size, cn, pn);
    return 1;
  }

  /* de-whiten the passphrase exactly as the ctor does */
  uint8_t wkey[32];
  sopk_whiten_key(blob, SOPK_WHITEN_SPAN, wkey);
  /* mirrors SOPK_MAX_PASS in stub/sopk_rt.c, which bounds the same stack copy
   */
  char pass[256];
  if (w->pass_len >= sizeof pass) {
    printf("FAIL: pass_len %u too large\n", w->pass_len);
    return 1;
  }
  memcpy(pass, wpass, w->pass_len);
  sopk_chacha20_apply((uint8_t *)pass, w->pass_len, wkey, SOPK_WHITEN_NONCE);
  pass[w->pass_len] = '\0';

  /* Assert the tier BEFORE opening. A direct assertion beats timing the open:
   * this probe runs on the pack host, so any millisecond threshold needs
   * host-variance slack and still would not say *why* it was slow. This also
   * fails to COMPILE against a pre-3.0.0 wbcrypto.h (unknown type
   * wbc_kdf_tier), which makes it an earlier version tripwire than valid_wbc().
   */
  wbc_kdf_tier tier = WBC_KDF_HIGH;
  wbc_status ts = wbc_blob_kdf_tier(blob, w->blob_len, &tier);
  if (ts != WBC_OK) {
    printf("FAIL: wbc_blob_kdf_tier -> %s\n", wbc_strerror(ts));
    printf("      the blob is truncated, not a WBTS blob, or a foreign format "
           "version\n");
    return 1;
  }
  printf("  blob kdf tier = %d (0 = light/HKDF)\n", (int)tier);
  if (tier != WBC_KDF_NONE) {
    printf("FAIL: blob was sealed at KDF tier %d, expected 0 (light).\n",
           (int)tier);
    printf("      provision.py passes --kdf light, so either the host "
           "wb_keygen ignored it\n"
           "      (pre-3.0.0 tool) or provision._seal stopped passing it. At "
           "`heavy` this\n"
           "      costs ~266 ms of Argon2id and a transient 64 MiB per library "
           "on device.\n");
    return 1;
  }

  wbc_ctx *ctx = NULL;
  double t0 = ms();
  wbc_status s = wbc_open(blob, w->blob_len, pass, &ctx);
  double t_open = ms() - t0;
  if (s != WBC_OK) {
    printf("FAIL: wbc_open -> %s\n", wbc_strerror(s));
    printf("      a wrong passphrase here means the whitening mirror drifted "
           "(sopack/cipher.py <-> stub/stub_cipher.h)\n");
    return 1;
  }
  printf("  wbc_open OK (%.1f ms)\n", t_open);

  uint8_t sk[WBC_SESSION_KEY_BYTES];
  t0 = ms();
  s = wbc_unwrap_key(ctx, r->wrapped, sk);
  double t_unwrap = ms() - t0;
  wbc_close(ctx);
  if (s != WBC_OK) {
    printf("FAIL: wbc_unwrap_key -> %s\n", wbc_strerror(s));
    return 1;
  }
  printf("  wbc_unwrap_key OK (%.2f ms)\n", t_unwrap);

  t0 = ms();
  sopk_chacha20_apply(ct, cn, sk, r->nonce16);
  double t_bulk = ms() - t0;
  wbc_wipe(sk, sizeof sk);
  printf("  ChaCha20 decrypt: %.1f ms (%.0f MB/s)\n", t_bulk,
         cn / 1e6 / (t_bulk / 1e3));

  int ok = memcmp(ct, pt, pn) == 0;
  if (!ok)
    printf(
        "  compare FAILED: the ChaCha20 mirror or the key wrap has drifted\n");
  printf("\nROUND-TRIP: %s   (total %.1f ms for %zu bytes)\n",
         ok ? "PASS" : "FAIL", t_open + t_unwrap + t_bulk, pn);
  return ok ? 0 : 1;
}
