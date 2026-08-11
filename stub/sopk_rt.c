/*
 * sopk_rt.c — REFERENCE source for the white-box runtime helper used by
 * sopack's
 * `--cipher wbaes` mode. This is the THIN per-target helper: it triggers on its
 * own target and does the bulk decrypt, but links no white-box (see
 * stub/sopk_wb.c for the shared provider, and stub/sopk_wb.h for why the work
 * is split this way). The USER builds it per ABI with the Android NDK + O-MVLL:
 *
 * THE BUILD COMMAND AND ITS RATIONALE LIVE IN docs/wbaes-verification.md PHASE
 * 4 (step 4b). It is not repeated here, because two copies drift: use that one.
 * Since the v3 split this is the SIMPLER of the two links — plain clang, no
 * static libc++, no `-x c` dance, no libwbcrypto.a — but it must be linked
 * AGAINST the already-built libsopk_wb.so so that
 * --no-undefined still holds and the DT_NEEDED string comes from the provider's
 * DT_SONAME.
 *
 * Result: a normal Android .so whose DT_NEEDED are bionic libs
 * (libc/libm/libdl, + liblog if built with -DSOPK_RT_LOG) plus exactly one
 * more: libsopk_wb.so, the shared provider. It exports nothing. sopack then,
 * per target: clones this skeleton, renames DT_SONAME/filename to
 * libsopk_rt_<target>.so, appends the sopk_rt_region as a read-only PT_LOAD,
 * and injects the soname as a DT_NEEDED of the target. See stub/sopk_rt.h and
 * stub/sopk_wb.h.
 *
 * The constructor runs before the target's own init (dependency-first ordering)
 * and: locate own region -> find target -> sopk_wb_k() into the SHARED
 * provider, which owns the blob/passphrase and returns this target's session
 * key -> copy .text page window into anon RW -> ChaCha20-decrypt with the
 * session key -> wipe the session key -> mremap onto the original .text VA
 * (execmem, not execmod) -> mprotect R-X -> flush I-cache. On ANY error it
 * FAILS CLOSED: sopk_fail() records a numbered reason in sopk_fail_code and
 * abort()s.
 *
 * Why fail closed here, when the freestanding stub deliberately fails open (see
 * docs/architecture.md §4c/§9b): the stub can chain the original DT_INIT and
 * genuinely degrade to an unpacked-but-working library. This helper has no such
 * fallback — its only job is decryption, so a failure leaves the target
 * executing still-encrypted .text, which SIGILLs somewhere inside the target
 * with nothing pointing at the cause. Aborting does not add a crash; it moves
 * the same crash to the real cause with a controlled signature, and
 * sopk_fail_code stays readable in the tombstone even in a stripped,
 * non-logging build.
 *
 * Why the white-box does not decrypt `.text` itself: it runs at well under 1
 * MB/s (every block is thousands of obfuscated VM instructions), so a multi-MB
 * `.text` took minutes. 2.0.0 removed the bulk entry points outright. The
 * white-box now protects only the long-term key; the session key it unwraps
 * drives a conventional stream cipher.
 */
#include <link.h> /* dl_iterate_phdr, ElfW           */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h> /* abort                           */
#include <string.h>
#include <sys/auxv.h> /* getauxval(AT_PAGESZ)            */
#include <sys/mman.h> /* mmap, mremap, mprotect, munmap  */

#include "sopk_rt.h"     /* region contract                 */
#include "sopk_wb.h"     /* sopk_wb_k — the shared provider's ONE export */
#include "stub_cipher.h" /* sopk_chacha20_apply (the bulk .text cipher) */

/* NOTE: this file links NO white-box. Every wbc_* call, the wbcrypto.h include
 * and the WBC_*_BYTES static assertions live in stub/sopk_wb.c (the shared
 * provider). That is what makes this artifact a few KB instead of ~465 KB, and
 * it is why the packer expects ZERO `wbc_` / `sodium_` references here — any at
 * all means it was built from the wrong source, or linked libwbcrypto.a by
 * mistake. */

/* Retained build marker — see the SOPK_RT_BUILD_MARKER_BYTES note in sopk_rt.h.
 * `used` stops the compiler dropping it; `retain` (SHF_GNU_RETAIN) stops
 * --gc-sections doing so. The ctor also touches it, so it survives toolchains
 * that honour neither. */
#if defined(__has_attribute)
#if __has_attribute(retain)
#define SOPK_RT_RETAIN __attribute__((retain))
#endif
#endif
#ifndef SOPK_RT_RETAIN
#define SOPK_RT_RETAIN
#endif
__attribute__((used)) SOPK_RT_RETAIN static const uint8_t
    sopk_rt_build_marker[SOPK_RT_BUILD_MARKER_LEN] = SOPK_RT_BUILD_MARKER_BYTES;

#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif
#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif

/* Opt-in logcat tracing for on-device verification/debugging. Build the
 * skeleton with
 * `-DSOPK_RT_LOG -llog` to see each step under `adb logcat -s sopk_rt`; omit
 * for release (then the helper does no logging and needs no liblog). */
#ifdef SOPK_RT_LOG
#include <android/log.h>
#define SOPK_LOG(...)                                                          \
  __android_log_print(ANDROID_LOG_INFO, "sopk_rt", __VA_ARGS__)
#else
#define SOPK_LOG(...) ((void)0)
#endif

/* Per-phase timing, on the same switch as the logging. Macros rather than
 * inline #ifdefs so the ctor stays readable; declaration and initialiser must
 * live in ONE macro (SOPK_MEASURE) so both vanish together in a release build.
 * Only the ChaCha20 phase scales with .text size; the sopk_wb_k phase (HKDF +
 * Unseal of the ~455 KB blob, then two white-box blocks) is fixed per library.
 * Before wbcrypto 3.0.0 that phase was Argon2id and dominated everything at
 * ~266 ms on device; sopack now seals at the `light` KDF tier. See
 * provision.py. */
#ifdef SOPK_RT_LOG
#include <time.h>
static double sopk_now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}
#define SOPK_TIMER(v) double v = sopk_now_ms()
#define SOPK_RESET(v) ((v) = sopk_now_ms())
#define SOPK_MEASURE(ms, t) double ms = (sopk_now_ms() - (t))
#else
#define SOPK_TIMER(v) ((void)0)
#define SOPK_RESET(v) ((void)0)
#define SOPK_MEASURE(ms, t) ((void)0)
#endif

/* Fail closed. `volatile` keeps the store from being optimised away, so the
 * reason survives into a release build where there is no logging: the code is
 * readable in the tombstone's memory dump. `noreturn` lets the compiler drop
 * the dead code after every call site, so failing closed costs no bytes over
 * failing open. Codes are stable — do not renumber. */
enum {
  SOPK_FAIL_NO_REGION = 1,
  SOPK_FAIL_BAD_FIELDS = 2,
  SOPK_FAIL_NO_TARGET = 3,
  /* 4 and 5 were WBC_OPEN / WBC_UNWRAP, performed here before the v3 provider
   * split. RETIRED, NOT REUSED: a tombstone from an older build must not be
   * misread as a new failure mode. The provider reports those two as reasons 7
   * and 8 -> codes 17 and 18. */
  SOPK_FAIL_SCRATCH_MMAP = 6,
  SOPK_FAIL_FIXED_REMAP = 7,
  SOPK_FAIL_MPROTECT = 8,
  SOPK_FAIL_REGION_TAIL = 9,
  /* The shared provider's reason codes are folded in as SOPK_FAIL_WB_CALL +
   * reason, i.e. the 10..19 band (see sopk_wb.h). 11=arg 12=abi 13=region
   * 14=fields 15=tail 16=tier 17=wbc_open 18=wbc_unwrap. A bare 10 would mean
   * reason 0, which cannot fail. */
  SOPK_FAIL_WB_CALL = 10,
};

static volatile unsigned int sopk_fail_code;

__attribute__((noreturn)) static void sopk_fail(unsigned int code) {
  sopk_fail_code = code;
  abort();
}

#ifdef SOPK_RT_LOG
#define SOPK_FAIL(code, ...)                                                   \
  do {                                                                         \
    SOPK_LOG(__VA_ARGS__);                                                     \
    sopk_fail(code);                                                           \
  } while (0)
#else
#define SOPK_FAIL(code, ...) sopk_fail(code)
#endif

/* Local session-key wipe. This file no longer links the white-box, so wbc_wipe
 * is gone — leaving a call to it here would fail the --no-undefined link, which
 * is the right outcome but only if the reason is written down. `volatile` stops
 * the compiler eliding the store as a dead write to a soon-dead stack buffer.
 */
static void sopk_wipe(void *p, size_t n) {
  volatile unsigned char *q = (volatile unsigned char *)p;
  while (n--)
    *q++ = 0;
}

static uintptr_t align_down(uintptr_t v, uintptr_t a) { return v & ~(a - 1); }
static uintptr_t align_up(uintptr_t v, uintptr_t a) {
  return (v + a - 1) & ~(a - 1);
}

/* ---- locate our own appended region
 * ------------------------------------------------ */
struct self_scan {
  uintptr_t selfaddr;
  const uint8_t *region;
  size_t size;
};

static int self_cb(struct dl_phdr_info *info, size_t sz, void *data) {
  (void)sz;
  struct self_scan *s = (struct self_scan *)data;
  ElfW(Addr) base = info->dlpi_addr;

  /* Is our own code address inside this module? */
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

  /* Among our own read-only PT_LOADs, pick the one that starts with the region
   * magic. */
  for (int i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
    if (ph->p_type != PT_LOAD)
      continue;
    if (ph->p_flags & (PF_W | PF_X))
      continue; /* region is R-only */
    const uint8_t *p = (const uint8_t *)((uintptr_t)base + ph->p_vaddr);
    if (ph->p_memsz < SOPK_RT_REGION_HDR_SIZE)
      continue;
    const sopk_rt_region *r = (const sopk_rt_region *)p;
    if (r->magic == SOPK_RT_REGION_MAGIC &&
        r->version == SOPK_RT_REGION_VERSION) {
      s->region = p;
      s->size = (size_t)ph->p_memsz; /* bounds the variable-length tail */
      return 1;                      /* stop iteration */
    }
  }
  return 1; /* found self but no region -> stop; the ctor then fails closed */
}

/* ---- locate the target by soname basename
 * ------------------------------------------ */
struct tgt_scan {
  const char *soname;
  uint16_t soname_len;
  ElfW(Addr) base;
  int found;
};

static const char *basename_of(const char *path) {
  const char *b = path;
  for (const char *p = path; *p; p++)
    if (*p == '/')
      b = p + 1;
  return b;
}

static int tgt_cb(struct dl_phdr_info *info, size_t sz, void *data) {
  (void)sz;
  struct tgt_scan *t = (struct tgt_scan *)data;
  if (!info->dlpi_name)
    return 0;
  const char *bn = basename_of(info->dlpi_name);
  size_t bl = strlen(bn);
  if (bl == t->soname_len && memcmp(bn, t->soname, bl) == 0) {
    t->base = info->dlpi_addr;
    t->found = 1;
    return 1;
  }
  return 0;
}

__attribute__((constructor)) static void sopk_rt_ctor(void) {
  SOPK_TIMER(t_ctor);

  /* Keep the build marker reachable regardless of toolchain GC behaviour. */
  __asm__ __volatile__("" ::"r"(sopk_rt_build_marker));

  struct self_scan ss = {(uintptr_t)&sopk_rt_ctor, NULL, 0};
  dl_iterate_phdr(self_cb, &ss);
  if (!ss.region)
    SOPK_FAIL(SOPK_FAIL_NO_REGION, "no metadata region found in self");

  const sopk_rt_region *r = (const sopk_rt_region *)ss.region;
  const uint8_t *tail = ss.region + SOPK_RT_REGION_HDR_SIZE;
  const char *soname = (const char *)tail;
  uint64_t text_rva = r->text_rva;
  uint64_t text_size = r->text_size;
  if (text_size == 0 || r->soname_len == 0)
    SOPK_FAIL(SOPK_FAIL_BAD_FIELDS, "bad region fields");

  /* self_cb only proved the 96-byte HEADER fits. The tail is variable-length
   * and its length comes from the region itself, so bound it against the
   * segment before reading through soname — otherwise a truncated or
   * hand-edited region walks off the end of the mapping. Computed in the
   * segment's own units to avoid pointer overflow. */
  if ((uint64_t)SOPK_RT_REGION_HDR_SIZE + r->soname_len > (uint64_t)ss.size)
    SOPK_FAIL(SOPK_FAIL_REGION_TAIL, "region tail exceeds segment");
  SOPK_LOG("region: target='%.*s' text_rva=0x%llx size=%llu",
           (int)r->soname_len, soname, (unsigned long long)text_rva,
           (unsigned long long)text_size);

  /* find the target's load base */
  struct tgt_scan ts = {soname, r->soname_len, 0, 0};
  dl_iterate_phdr(tgt_cb, &ts);
  if (!ts.found)
    SOPK_FAIL(SOPK_FAIL_NO_TARGET, "target '%.*s' not loaded",
              (int)r->soname_len, soname);

  /* Unwrap our session key through the SHARED provider (libsopk_wb.so), which
   * owns the sealed blob, the passphrase and every wbc_* call. This file links
   * no white-box at all.
   *
   * The provider never aborts — it returns a reason code and we own failing
   * closed, so the tombstone names the step rather than blaming the shared
   * object. Its codes are folded into the 10..19 band; see sopk_wb.h for the
   * list. A link-time note: if libsopk_wb.so is missing at runtime bionic
   * cannot load THIS helper either, which fails the target's dlopen far from
   * the cause — the packer therefore asserts the dependency is present and
   * staged. */
  SOPK_TIMER(t_phase);
  uint8_t sk[SOPK_RT_SESSION_KEY_BYTES];
  int wrc = sopk_wb_k(SOPK_WB_ABI, r->wrapped, SOPK_RT_WRAPPED_KEY_BYTES, sk,
                      sizeof(sk));
  if (wrc != SOPK_WB_OK) {
    sopk_wipe(sk, sizeof(sk)); /* wipe before aborting, not after */
    SOPK_FAIL(SOPK_FAIL_WB_CALL + (unsigned)wrc,
              "sopk_wb_k failed (provider reason %d)", wrc);
  }
  /* ONE phase, not two. Since the v3 split this single call covers the
   * provider's whole job — de-whiten, wbc_open, wbc_unwrap_key, wbc_close — so
   * there is nothing left here to time separately. An earlier version reported
   * a bogus `unwrap=0.00ms` next to it, which read as "the white-box unwrap
   * became free" rather than "this number measures nothing". For the per-step
   * breakdown inside the provider, build it with -DSOPK_RT_LOG and read logcat
   * tag `sopk_wb`. */
  SOPK_MEASURE(ms_wb, t_phase);

  uintptr_t pg = (uintptr_t)getauxval(AT_PAGESZ);
  if (pg == 0)
    pg = 4096;
  uintptr_t text = (uintptr_t)ts.base + (uintptr_t)text_rva;
  uintptr_t win_lo = align_down(text, pg);
  uintptr_t win_hi = align_up(text + text_size, pg);
  size_t win_len = (size_t)(win_hi - win_lo);

  /* copy the encrypted page window into fresh anonymous RW memory */
  SOPK_RESET(t_phase);
  void *scratch = mmap(NULL, win_len, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (scratch == MAP_FAILED) {
    sopk_wipe(sk, sizeof(sk));
    SOPK_FAIL(SOPK_FAIL_SCRATCH_MMAP, "scratch mmap failed");
  }
  memcpy(scratch, (const void *)win_lo, win_len);
  SOPK_MEASURE(ms_copy, t_phase);

  /* Decrypt exactly the .text sub-range, in place in the scratch copy. The
   * keystream is anchored at .text byte 0, not at the page-window start.
   * ChaCha20 is its own inverse, so this is the same call the packer used to
   * encrypt (sopack/cipher.py). */
  SOPK_RESET(t_phase);
  uint8_t *tin = (uint8_t *)scratch + (size_t)(text - win_lo);
  sopk_chacha20_apply(tin, (size_t)text_size, sk, r->nonce16);
  SOPK_MEASURE(ms_decrypt, t_phase);
  sopk_wipe(sk,
            sizeof(sk)); /* plaintext session key's job is done — drop it now */

  /* land the decrypted ANON pages onto the original .text VA -> SELinux execmem
   * path */
  SOPK_RESET(t_phase);
  void *placed = mremap(scratch, win_len, win_len,
                        MREMAP_MAYMOVE | MREMAP_FIXED, (void *)win_lo);
  if (placed == MAP_FAILED) {
    /* Fallback: replace the file mapping with a fresh fixed anon map + copy in.
     * MAP_FIXED already replaces whatever is at win_lo atomically, so do NOT
     * munmap first: an munmap+failed-mmap pair would leave the target with no
     * .text mapping at all, turning a recoverable failure into a segfault on
     * the first call into the library. (mremap with MREMAP_FIXED above unmaps
     * its destination implicitly too, so neither path needs the window
     * pre-unmapped.) */
    void *p = mmap((void *)win_lo, win_len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p == MAP_FAILED) {
      munmap(scratch, win_len);
      SOPK_FAIL(SOPK_FAIL_FIXED_REMAP, "fixed anon remap failed");
    }
    memcpy((void *)win_lo, scratch, win_len);
    munmap(scratch, win_len);
    SOPK_LOG("used MAP_FIXED fallback");
  }

  /* Must be checked: a failed mprotect leaves the decrypted window
   * RW-and-not-X, so the first call into .text faults — and the old code went
   * on to log "OK" regardless. */
  if (mprotect((void *)win_lo, win_len, PROT_READ | PROT_EXEC) != 0)
    SOPK_FAIL(SOPK_FAIL_MPROTECT, "mprotect R-X failed");
  __builtin___clear_cache((char *)text, (char *)(text + text_size));
  SOPK_MEASURE(ms_place, t_phase);

  SOPK_LOG("decrypted '%.*s' .text (%llu bytes) at 0x%lx — OK",
           (int)r->soname_len, soname, (unsigned long long)text_size,
           (long)text);
  /* `total` covers the whole ctor, so it also includes the phdr scans and the
   * passphrase de-whitening, which are not timed separately. */
  SOPK_MEASURE(ms_total, t_ctor);
  SOPK_LOG("timing '%.*s': wb=%.1fms copy=%.1fms decrypt=%.1fms "
           "place=%.1fms total=%.1fms (%.0f MB/s over %llu bytes)",
           (int)r->soname_len, soname, ms_wb, ms_copy, ms_decrypt, ms_place,
           ms_total,
           ms_decrypt > 0.0 ? (double)text_size / 1e6 / (ms_decrypt / 1e3)
                            : 0.0,
           (unsigned long long)text_size);
}
