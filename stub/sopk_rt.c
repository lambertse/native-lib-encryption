/*
 * sopk_rt.c — REFERENCE source for the white-box runtime helper used by sopack's
 * `--cipher wbaes` mode. Requires whitebox-cryptography >= 2.0.0 (key wrapping). The USER
 * builds this per ABI with the Android NDK + O-MVLL, statically linking the white-box VM:
 *
 * THE BUILD COMMAND AND ITS RATIONALE LIVE IN docs/wbaes-verification.md PHASE 4. It is not
 * repeated here, because two copies drift: use that one. In outline it is clang++ (not clang —
 * libwbcrypto.a is C++) with a static libc++, `-x c` for this file, and --no-undefined,
 * --exclude-libs, linking only libwbcrypto.a. Every one of those flags is load-bearing and the
 * doc says why, along with the three checks that prove the result is correct.
 *
 * Result: a normal Android .so whose ONLY DT_NEEDED are bionic libs (libc/libm/libdl,
 * + liblog if built with -DSOPK_RT_LOG) and which exports nothing. sopack then, per
 * target: clones this skeleton, renames DT_SONAME/filename to libsopk_rt_<target>.so,
 * appends the sopk_rt_region as a read-only PT_LOAD, and injects the soname as a
 * DT_NEEDED of the target. See stub/sopk_rt.h for the contract.
 *
 * The constructor runs before the target's own init (dependency-first ordering) and:
 *   locate own region -> find target -> de-whiten passphrase -> wbc_open ->
 *   wbc_unwrap_key (2 white-box blocks, ~1 ms) -> wbc_close ->
 *   copy .text page window into anon RW -> ChaCha20-decrypt with the session key ->
 *   wipe the session key -> mremap onto the original .text VA (execmem, not execmod) ->
 *   mprotect R-X -> flush I-cache. On ANY error it FAILS OPEN (returns), leaving the
 *   target to load normally on still-encrypted code (which then faults visibly) — never
 *   worse than a hard abort, and correct when the helper is present but a step is
 *   unsupported.
 *
 * Why the white-box does not decrypt `.text` itself: it runs at well under 1 MB/s (every
 * block is thousands of obfuscated VM instructions), so a multi-MB `.text` took minutes.
 * 2.0.0 removed the bulk entry points outright. The white-box now protects only the
 * long-term key; the session key it unwraps drives a conventional stream cipher.
 */
#include <link.h>          /* dl_iterate_phdr, ElfW           */
#include <sys/mman.h>      /* mmap, mremap, mprotect, munmap  */
#include <sys/auxv.h>      /* getauxval(AT_PAGESZ)            */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wbcrypto.h"      /* wbc_open / wbc_unwrap_key / wbc_wipe / ... (>= 2.0.0) */

#include "sopk_rt.h"       /* region contract                 */
#include "stub_cipher.h"   /* sopk_whiten_key / sopk_chacha20_apply / SOPK_WHITEN_NONCE */

/* Note: libsodium is initialised INSIDE libwbcrypto (storage::Unseal calls sodium_init()
 * before any use), so the helper neither includes <sodium.h> nor calls sodium_init. Since
 * 2.0.0 libwbcrypto.a bundles libsodium, so it is not a separate link input either. */

/* The region reserves fixed-size fields for the wrapped key and the session key length;
 * if a future SDK changes either, fail the BUILD rather than emit a wrong-length wrap. */
_Static_assert(SOPK_RT_WRAPPED_KEY_BYTES == WBC_WRAPPED_KEY_BYTES,
               "sopk_rt_region.wrapped must match WBC_WRAPPED_KEY_BYTES");
_Static_assert(SOPK_RT_SESSION_KEY_BYTES == WBC_SESSION_KEY_BYTES,
               "SOPK_RT_SESSION_KEY_BYTES must match WBC_SESSION_KEY_BYTES");

/* Retained build marker — see the SOPK_RT_BUILD_MARKER_BYTES note in sopk_rt.h. `used`
 * stops the compiler dropping it; `retain` (SHF_GNU_RETAIN) stops --gc-sections doing so.
 * The ctor also touches it, so it survives toolchains that honour neither. */
#if defined(__has_attribute)
#  if __has_attribute(retain)
#    define SOPK_RT_RETAIN __attribute__((retain))
#  endif
#endif
#ifndef SOPK_RT_RETAIN
#define SOPK_RT_RETAIN
#endif
__attribute__((used)) SOPK_RT_RETAIN
static const uint8_t sopk_rt_build_marker[SOPK_RT_BUILD_MARKER_LEN] =
    SOPK_RT_BUILD_MARKER_BYTES;

#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif
#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif

/* Opt-in logcat tracing for on-device verification/debugging. Build the skeleton with
 * `-DSOPK_RT_LOG -llog` to see each step under `adb logcat -s sopk_rt`; omit for release
 * (then the helper does no logging and needs no liblog). */
#ifdef SOPK_RT_LOG
#include <android/log.h>
#define SOPK_LOG(...) __android_log_print(ANDROID_LOG_INFO, "sopk_rt", __VA_ARGS__)
#else
#define SOPK_LOG(...) ((void)0)
#endif

/* Per-phase timing, on the same switch as the logging. Macros rather than inline #ifdefs so
 * the ctor stays readable; declaration and initialiser must live in ONE macro (SOPK_MEASURE)
 * so both vanish together in a release build. Only the ChaCha20 phase scales with .text size:
 * wbc_open is Argon2id and wbc_unwrap_key is two white-box blocks, both fixed. */
#ifdef SOPK_RT_LOG
#include <time.h>
static double sopk_now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}
#define SOPK_TIMER(v)         double v = sopk_now_ms()
#define SOPK_RESET(v)         ((v) = sopk_now_ms())
#define SOPK_MEASURE(ms, t)   double ms = (sopk_now_ms() - (t))
#else
#define SOPK_TIMER(v)         ((void)0)
#define SOPK_RESET(v)         ((void)0)
#define SOPK_MEASURE(ms, t)   ((void)0)
#endif

#define SOPK_MAX_PASS 256u   /* whitened passphrases are short; bound the stack copy */

static uintptr_t align_down(uintptr_t v, uintptr_t a) { return v & ~(a - 1); }
static uintptr_t align_up(uintptr_t v, uintptr_t a)   { return (v + a - 1) & ~(a - 1); }

/* ---- locate our own appended region ------------------------------------------------ */
struct self_scan { uintptr_t selfaddr; const uint8_t *region; };

static int self_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)sz;
    struct self_scan *s = (struct self_scan *)data;
    ElfW(Addr) base = info->dlpi_addr;

    /* Is our own code address inside this module? */
    int is_self = 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        uintptr_t lo = (uintptr_t)base + ph->p_vaddr;
        if (s->selfaddr >= lo && s->selfaddr < lo + ph->p_memsz) { is_self = 1; break; }
    }
    if (!is_self) return 0;

    /* Among our own read-only PT_LOADs, pick the one that starts with the region magic. */
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        if (ph->p_flags & (PF_W | PF_X)) continue;          /* region is R-only */
        const uint8_t *p = (const uint8_t *)((uintptr_t)base + ph->p_vaddr);
        if (ph->p_memsz < SOPK_RT_REGION_HDR_SIZE) continue;
        const sopk_rt_region *r = (const sopk_rt_region *)p;
        if (r->magic == SOPK_RT_REGION_MAGIC && r->version == SOPK_RT_REGION_VERSION) {
            s->region = p;
            return 1;                                       /* stop iteration */
        }
    }
    return 1;   /* found self but no region -> stop (fail open) */
}

/* ---- locate the target by soname basename ------------------------------------------ */
struct tgt_scan { const char *soname; uint16_t soname_len; ElfW(Addr) base; int found; };

static const char *basename_of(const char *path) {
    const char *b = path;
    for (const char *p = path; *p; p++) if (*p == '/') b = p + 1;
    return b;
}

static int tgt_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)sz;
    struct tgt_scan *t = (struct tgt_scan *)data;
    if (!info->dlpi_name) return 0;
    const char *bn = basename_of(info->dlpi_name);
    size_t bl = strlen(bn);
    if (bl == t->soname_len && memcmp(bn, t->soname, bl) == 0) {
        t->base = info->dlpi_addr;
        t->found = 1;
        return 1;
    }
    return 0;
}

__attribute__((constructor))
static void sopk_rt_ctor(void) {
    SOPK_TIMER(t_ctor);

    /* Keep the build marker reachable regardless of toolchain GC behaviour. */
    __asm__ __volatile__("" :: "r"(sopk_rt_build_marker));

    struct self_scan ss = { (uintptr_t)&sopk_rt_ctor, NULL };
    dl_iterate_phdr(self_cb, &ss);
    if (!ss.region) { SOPK_LOG("no metadata region found in self (fail open)"); return; }

    const sopk_rt_region *r = (const sopk_rt_region *)ss.region;
    const uint8_t *tail = ss.region + SOPK_RT_REGION_HDR_SIZE;
    const char    *soname = (const char *)tail;
    const uint8_t *wpass  = tail + r->soname_len;
    const uint8_t *blob   = wpass + r->pass_len;
    uint64_t text_rva  = r->text_rva;
    uint64_t text_size = r->text_size;
    uint32_t blob_len  = r->blob_len;
    uint16_t pass_len  = r->pass_len;
    if (text_size == 0 || blob_len < SOPK_WHITEN_SPAN || pass_len == 0
        || pass_len >= SOPK_MAX_PASS) { SOPK_LOG("bad region fields (fail open)"); return; }
    SOPK_LOG("region: target='%.*s' text_rva=0x%llx size=%llu blob=%u",
             (int)r->soname_len, soname, (unsigned long long)text_rva,
             (unsigned long long)text_size, blob_len);

    /* find the target's load base */
    struct tgt_scan ts = { soname, r->soname_len, 0, 0 };
    dl_iterate_phdr(tgt_cb, &ts);
    if (!ts.found) { SOPK_LOG("target '%.*s' not loaded (fail open)",
                              (int)r->soname_len, soname); return; }

    /* de-whiten the passphrase (key derived from the blob's own first bytes) */
    uint8_t wkey[32];
    sopk_whiten_key(blob, SOPK_WHITEN_SPAN, wkey);
    char pass[SOPK_MAX_PASS];
    memcpy(pass, wpass, pass_len);
    sopk_chacha20_apply((uint8_t *)pass, pass_len, wkey, SOPK_WHITEN_NONCE);
    pass[pass_len] = '\0';
    memset(wkey, 0, sizeof(wkey));

    SOPK_TIMER(t_phase);
    wbc_ctx *ctx = NULL;
    wbc_status st = wbc_open(blob, blob_len, pass, &ctx);
    memset(pass, 0, sizeof(pass));                          /* wipe ASAP */
    if (st != WBC_OK || !ctx) { SOPK_LOG("wbc_open failed (%d) (fail open)", (int)st); return; }
    SOPK_MEASURE(ms_open, t_phase);

    /* The ONLY white-box work: unwrap the session key (2 blocks, ~1 ms, independent of
     * .text size). Then close the context immediately — it holds a ~400 KB VM data image
     * that is dead weight for the rest of the ctor. */
    SOPK_RESET(t_phase);
    uint8_t sk[SOPK_RT_SESSION_KEY_BYTES];
    st = wbc_unwrap_key(ctx, r->wrapped, sk);
    wbc_close(ctx);
    if (st != WBC_OK) {
        SOPK_LOG("wbc_unwrap_key failed (%d) (fail open)", (int)st);
        wbc_wipe(sk, sizeof(sk));
        return;
    }
    SOPK_MEASURE(ms_unwrap, t_phase);

    uintptr_t pg = (uintptr_t)getauxval(AT_PAGESZ);
    if (pg == 0) pg = 4096;
    uintptr_t text   = (uintptr_t)ts.base + (uintptr_t)text_rva;
    uintptr_t win_lo = align_down(text, pg);
    uintptr_t win_hi = align_up(text + text_size, pg);
    size_t    win_len = (size_t)(win_hi - win_lo);

    /* copy the encrypted page window into fresh anonymous RW memory */
    SOPK_RESET(t_phase);
    void *scratch = mmap(NULL, win_len, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (scratch == MAP_FAILED) {
        SOPK_LOG("scratch mmap failed");
        wbc_wipe(sk, sizeof(sk));
        return;
    }
    memcpy(scratch, (const void *)win_lo, win_len);
    SOPK_MEASURE(ms_copy, t_phase);

    /* Decrypt exactly the .text sub-range, in place in the scratch copy. The keystream is
     * anchored at .text byte 0, not at the page-window start. ChaCha20 is its own inverse,
     * so this is the same call the packer used to encrypt (sopack/cipher.py). */
    SOPK_RESET(t_phase);
    uint8_t *tin = (uint8_t *)scratch + (size_t)(text - win_lo);
    sopk_chacha20_apply(tin, (size_t)text_size, sk, r->nonce16);
    SOPK_MEASURE(ms_decrypt, t_phase);
    wbc_wipe(sk, sizeof(sk));   /* plaintext session key's job is done — drop it now */

    /* land the decrypted ANON pages onto the original .text VA -> SELinux execmem path */
    SOPK_RESET(t_phase);
    void *placed = mremap(scratch, win_len, win_len,
                          MREMAP_MAYMOVE | MREMAP_FIXED, (void *)win_lo);
    if (placed == MAP_FAILED) {
        /* fallback: replace the file mapping with a fresh fixed anon map + copy in */
        munmap((void *)win_lo, win_len);
        void *p = mmap((void *)win_lo, win_len, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (p == MAP_FAILED) { SOPK_LOG("fixed anon remap failed"); munmap(scratch, win_len); return; }
        memcpy((void *)win_lo, scratch, win_len);
        munmap(scratch, win_len);
        SOPK_LOG("used munmap+MAP_FIXED fallback");
    }

    mprotect((void *)win_lo, win_len, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char *)text, (char *)(text + text_size));
    SOPK_MEASURE(ms_place, t_phase);

    SOPK_LOG("decrypted '%.*s' .text (%llu bytes) at 0x%lx — OK",
             (int)r->soname_len, soname, (unsigned long long)text_size, (long)text);
    /* `total` covers the whole ctor, so it also includes the phdr scans and the passphrase
     * de-whitening, which are not timed separately. */
    SOPK_MEASURE(ms_total, t_ctor);
    SOPK_LOG("timing '%.*s': open=%.1fms unwrap=%.2fms copy=%.1fms decrypt=%.1fms "
             "place=%.1fms total=%.1fms (%.0f MB/s over %llu bytes)",
             (int)r->soname_len, soname, ms_open, ms_unwrap, ms_copy, ms_decrypt, ms_place,
             ms_total,
             ms_decrypt > 0.0 ? (double)text_size / 1e6 / (ms_decrypt / 1e3) : 0.0,
             (unsigned long long)text_size);
}
