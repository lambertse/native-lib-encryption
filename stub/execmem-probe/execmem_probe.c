/*
 * phase0.c - standalone runtime-path spike (see docs/technical/ARCHITECTURE.md
 * §7, step 1).
 *
 * Proves the riskiest assumption BEFORE trusting the injector: that an app can
 * copy file-backed .text into anonymous memory, mremap it back ONTO the
 * original .text VA, flip it to R-X, and execute it - with no SELinux `avc:
 * denied` and no SIGSEGV - on real Android 14/15 and a 16 KB-page device.
 *
 * Unlike the injected stub this is NOT freestanding: it may use libc/liblog
 * because it is compiled as a normal .so. Load it FROM AN APP
 * (System.loadLibrary) so it runs in the untrusted_app SELinux domain - an `adb
 * shell` executable runs in the `shell` domain and would NOT be a
 * representative test. Watch:  adb logcat -s sopack-phase0
 */
#include <android/log.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define LOG(...)                                                               \
  __android_log_print(ANDROID_LOG_INFO, "sopack-phase0", __VA_ARGS__)

/* A self-contained target: no .rodata / helper deps, so a bare page move
 * suffices. */
static int __attribute__((noinline, used)) target(int x) {
  return x * 7 + 3; /* target(5) == 38 */
}

static uintptr_t align_down(uintptr_t v, uintptr_t a) { return v & ~(a - 1); }
static uintptr_t align_up(uintptr_t v, uintptr_t a) {
  return (v + a - 1) & ~(a - 1);
}

__attribute__((constructor)) static void spike(void) {
  size_t pg = (size_t)sysconf(_SC_PAGESIZE);
  LOG("page size = %zu", pg);

  uintptr_t t = (uintptr_t)&target;
  uintptr_t lo = align_down(t, pg);
  uintptr_t hi = align_up(t + 256, pg); /* target is tiny; one/two pages */
  size_t len = hi - lo;

  void *scratch = mmap(NULL, len, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (scratch == MAP_FAILED) {
    LOG("mmap FAILED");
    return;
  }

  memcpy(scratch, (void *)lo, len); /* copy the (plaintext) window */
  /* phase0 does not decrypt - it only validates the move+exec path. */

  void *placed =
      mremap(scratch, len, len, MREMAP_MAYMOVE | MREMAP_FIXED, (void *)lo);
  if (placed == MAP_FAILED) {
    LOG("mremap FIXED FAILED (errno path)");
    return;
  }

  if (mprotect((void *)lo, len, PROT_READ | PROT_EXEC) != 0) {
    LOG("mprotect R-X FAILED (execmem denied?)");
    return;
  }
  __builtin___clear_cache((char *)lo, (char *)lo + len);

  int r = target(5);
  LOG("target(5) = %d (expect 38) - mremap-onto-base %s", r,
      r == 38 ? "OK" : "WRONG");
}
