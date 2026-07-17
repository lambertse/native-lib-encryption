/*
 * stub.c — the injected runtime decryption stub.
 *
 * Lifecycle: the injector appends this compiled blob to the target .so as a fresh
 * R+X PT_LOAD (via PT_NOTE->PT_LOAD), and points the library's DT_INIT at
 * sopk_entry(). The dynamic linker calls DT_INIT after relocation + RELRO, before
 * DT_INIT_ARRAY and before any exported function — a safe, single-threaded window.
 *
 * What it does (W^X / SELinux `execmem` safe, per handover.md §3B):
 *   1. Find the target .text at runtime WITHOUT the load bias, using the address of
 *      g_decinfo (which the compiler references PC-relatively) + a signed delta the
 *      injector baked in.
 *   2. mmap an anonymous RW scratch region the size of the page-aligned .text window.
 *   3. Copy the (encrypted) window in, decrypt only the exact .text sub-range.
 *   4. mremap(MREMAP_FIXED) the scratch pages onto the ORIGINAL .text virtual address.
 *      Destination becomes anonymous -> the later exec transition is an `execmem`
 *      check (allowed to apps), never `execmod` (denied). Keeping .text at its
 *      original VA keeps every PC-relative ref, GOT/PLT use and unwind table valid.
 *   5. mprotect R-X, flush I-cache (arm), then chain the original DT_INIT if any.
 *
 * Constraints: no libc calls, no external symbols, no writable globals that would
 * land in .bss (blob is flat). Only g_decinfo is a global and it is initialized so
 * it lands in a PROGBITS section that the injector can find and patch.
 */
#include <stdint.h>
#include <stddef.h>
#include "decinfo.h"
#include "syscalls.h"
#include "stub_cipher.h"
#include "stub_log.h"

/*
 * The metadata record. Initialized (magic set) so the linker emits it into the blob
 * image rather than .bss. Placed in its own section so the build script and injector
 * can locate it. `used` + `retain` keep it from being stripped.
 *
 * MUST be `volatile`: the injector patches these fields AFTER compilation, so the
 * compiler must not constant-fold reads using the initializer values (if it did, it
 * would see text_size==0 and compile the whole stub away). `volatile` forces every
 * field read to go through memory.
 *
 * It lives in the injected R+X segment and is therefore READ-ONLY at runtime — the
 * stub only reads it, never writes it (volatile reads of read-only memory are fine).
 * DT_INIT is invoked exactly once by the linker, so no re-entry guard is needed.
 */
__attribute__((used, retain, section(".sopk_info")))
volatile sopk_decinfo g_decinfo = {
    .magic = SOPK_MAGIC,
    .version = SOPK_VERSION,
    .cipher_id = SOPK_CIPHER_CHACHA20,
    .flags = 0,
    .delta_text = 0,
    .text_size = 0,
    .delta_init = 0,
    .key = {0},
    .nonce = {0},
    .reserved = {0},
};

static inline uintptr_t sopk_align_down(uintptr_t v, uintptr_t a) {
    return v & ~(a - 1);
}
static inline uintptr_t sopk_align_up(uintptr_t v, uintptr_t a) {
    return (v + a - 1) & ~(a - 1);
}

/* bionic calls DT_INIT / DT_INIT_ARRAY entries as void(int, char**, char**). */
typedef void (*sopk_init_fn)(int, char **, char **);

/*
 * sopk_entry — DT_INIT target. Accepts and forwards (argc, argv, envp) so a chained
 * original init receives the arguments bionic would have passed it.
 */
__attribute__((used, retain, visibility("default")))
void sopk_entry(int argc, char **argv, char **envp) {
    /* g_decinfo is volatile; copy every needed field into non-volatile locals so the
     * cipher/logic run on real (patched) values and nothing is constant-folded. The
     * runtime address of g_decinfo is our anchor: all targets are reached by adding a
     * signed delta to it (no load bias needed). */
    volatile sopk_decinfo *src = &g_decinfo;
    uintptr_t self = (uintptr_t)src;

    uint32_t magic     = src->magic;
    uint64_t text_size = src->text_size;
    uint32_t cipher_id = src->cipher_id;
    uint32_t flags     = src->flags;
    int64_t  delta_text = src->delta_text;
    int64_t  delta_init = src->delta_init;
    uint8_t  key[32], nonce[16];
    for (int i = 0; i < 32; i++) key[i] = src->key[i];
    for (int i = 0; i < 16; i++) nonce[i] = src->nonce[i];

    sopk_dbg("[sopk] A:entry\n");
    if (magic != SOPK_MAGIC || text_size == 0)
        goto chain;                                       /* not patched — just chain */

    uintptr_t text = self + (intptr_t)delta_text;         /* runtime .text base */
    size_t    tlen = (size_t)text_size;

    size_t pg = sopk_page_size();
    uintptr_t win_lo = sopk_align_down(text, pg);
    uintptr_t win_hi = sopk_align_up(text + tlen, pg);
    size_t    win_len = win_hi - win_lo;

    /* 1. anon RW scratch */
    sopk_dbg("[sopk] B:mmap\n");
    void *scratch = sopk_mmap_anon(win_len);
    if (scratch == SOPK_MAP_FAILED) goto chain;           /* fail open: leave as-is */

    /* 2. copy the page window verbatim (encrypted .text + any plaintext neighbors) */
    sopk_dbg("[sopk] C:memcpy\n");
    sopk_memcpy(scratch, (void *)win_lo, win_len);

    /* 3. decrypt ONLY the exact .text sub-range inside the scratch copy */
    sopk_dbg("[sopk] D:decrypt\n");
    uint8_t *text_in_scratch = (uint8_t *)scratch + (text - win_lo);
    sopk_decrypt(text_in_scratch, tlen, cipher_id, key, nonce);

    /* 4. move decrypted pages onto the ORIGINAL .text VA (anon dest => execmem path) */
    sopk_dbg("[sopk] E:mremap\n");
    void *placed = sopk_mremap_fixed(scratch, win_len, (void *)win_lo);
    if (placed == SOPK_MAP_FAILED) goto chain;

    /* 5. RW -> R-X, then flush I-cache before anything executes there */
    sopk_dbg("[sopk] F:mprotect\n");
    sopk_mprotect((void *)win_lo, win_len, SOPK_PROT_READ | SOPK_PROT_EXEC);
    sopk_dbg("[sopk] G:flush\n");
    sopk_clear_icache((void *)text, (void *)(text + tlen));
    sopk_dbg("[sopk] H:done\n");

    if (flags & SOPK_FLAG_LOG)
        sopk_logcat("sopack", "native .text decrypted OK");

chain:
    if (flags & SOPK_FLAG_CHAIN_INIT) {
        sopk_init_fn orig = (sopk_init_fn)(self + (intptr_t)delta_init);
        orig(argc, argv, envp);
    }
}
