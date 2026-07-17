/*
 * syscalls.h — freestanding Linux syscall wrappers for arm64, x86_64, arm (EABI).
 *
 * The stub is injected into arbitrary .so files, so it must not depend on libc
 * being reachable through a PLT/GOT that we did not set up. We therefore issue raw
 * syscalls via inline assembly and implement the few libc-ish helpers we need
 * (memcpy) ourselves. No external symbols => no dynamic relocations in the blob.
 */
#ifndef SOPK_SYSCALLS_H
#define SOPK_SYSCALLS_H

#include <stdint.h>
#include <stddef.h>

/* ---- syscall numbers (per ABI) ---- */
#if defined(__aarch64__)
#  define SOPK_NR_mmap     222
#  define SOPK_NR_mprotect 226
#  define SOPK_NR_mremap   216
#  define SOPK_NR_munmap   215
#  define SOPK_NR_openat   56
#  define SOPK_NR_read     63
#  define SOPK_NR_write    64
#  define SOPK_NR_close    57
#elif defined(__x86_64__)
#  define SOPK_NR_mmap     9
#  define SOPK_NR_mprotect 10
#  define SOPK_NR_mremap   25
#  define SOPK_NR_munmap   11
#  define SOPK_NR_openat   257
#  define SOPK_NR_read     0
#  define SOPK_NR_write    1
#  define SOPK_NR_close    3
#elif defined(__arm__)
/* ARM EABI. Note: uses mmap2 (offset in pages), not mmap. */
#  define SOPK_NR_mmap2    192
#  define SOPK_NR_mprotect 125
#  define SOPK_NR_mremap   163
#  define SOPK_NR_munmap   91
#  define SOPK_NR_openat   322
#  define SOPK_NR_read     3
#  define SOPK_NR_write    4
#  define SOPK_NR_close    6
#  define SOPK_NR_cacheflush 0xf0002  /* __ARM_NR_cacheflush */
#else
#  error "unsupported architecture for sopack stub"
#endif

/* ---- raw syscall (up to 6 args) ---- */
#if defined(__aarch64__)
static inline long sopk_syscall6(long n, long a, long b, long c,
                                 long d, long e, long f) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
}
#elif defined(__x86_64__)
static inline long sopk_syscall6(long n, long a, long b, long c,
                                 long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8")  = e;
    register long r9  __asm__("r9")  = f;
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory", "cc");
    return ret;
}
#elif defined(__arm__)
static inline long sopk_syscall6(long n, long a, long b, long c,
                                 long d, long e, long f) {
    register long r7 __asm__("r7") = n;
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r3 __asm__("r3") = d;
    register long r4 __asm__("r4") = e;
    register long r5 __asm__("r5") = f;
    __asm__ volatile("svc #0"
                     : "+r"(r0)
                     : "r"(r7), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
                     : "memory", "cc");
    return r0;
}
#endif

#define sopk_syscall0(n)             sopk_syscall6((n),0,0,0,0,0,0)
#define sopk_syscall1(n,a)           sopk_syscall6((n),(long)(a),0,0,0,0,0)
#define sopk_syscall2(n,a,b)         sopk_syscall6((n),(long)(a),(long)(b),0,0,0,0)
#define sopk_syscall3(n,a,b,c)       sopk_syscall6((n),(long)(a),(long)(b),(long)(c),0,0,0)
#define sopk_syscall4(n,a,b,c,d)     sopk_syscall6((n),(long)(a),(long)(b),(long)(c),(long)(d),0,0)
#define sopk_syscall5(n,a,b,c,d,e)   sopk_syscall6((n),(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),0)

/* ---- mmap / mprotect / mremap prot & flag constants ---- */
#define SOPK_PROT_READ  0x1
#define SOPK_PROT_WRITE 0x2
#define SOPK_PROT_EXEC  0x4
#define SOPK_MAP_PRIVATE   0x02
#define SOPK_MAP_ANONYMOUS 0x20
#define SOPK_MREMAP_MAYMOVE 1
#define SOPK_MREMAP_FIXED   2
#define SOPK_MAP_FAILED ((void*)-1)
#define SOPK_O_RDONLY 0

static inline void *sopk_mmap_anon(size_t len) {
#if defined(__arm__)
    /* mmap2 offset is in 4096-byte units; anon => 0. */
    return (void *)sopk_syscall6(SOPK_NR_mmap2, 0, (long)len,
                                 SOPK_PROT_READ | SOPK_PROT_WRITE,
                                 SOPK_MAP_PRIVATE | SOPK_MAP_ANONYMOUS, -1, 0);
#else
    return (void *)sopk_syscall6(SOPK_NR_mmap, 0, (long)len,
                                 SOPK_PROT_READ | SOPK_PROT_WRITE,
                                 SOPK_MAP_PRIVATE | SOPK_MAP_ANONYMOUS, -1, 0);
#endif
}

static inline int sopk_mprotect(void *addr, size_t len, int prot) {
    return (int)sopk_syscall3(SOPK_NR_mprotect, addr, len, prot);
}

/* mremap(old, old_sz, new_sz, flags, new_addr) */
static inline void *sopk_mremap_fixed(void *old, size_t sz, void *dst) {
    return (void *)sopk_syscall5(SOPK_NR_mremap, old, sz, sz,
                                 SOPK_MREMAP_MAYMOVE | SOPK_MREMAP_FIXED, dst);
}

/* ---- debug marker to stderr (compiled in only with -DSOPK_DEBUG) ---- */
#ifdef SOPK_DEBUG
static inline void sopk_dbg(const char *s) {
    size_t n = 0; while (s[n]) n++;
    sopk_syscall3(SOPK_NR_write, 2, s, (long)n);
}
#else
#  define sopk_dbg(s) ((void)0)
#endif

/* ---- tiny freestanding memcpy ---- */
static inline void sopk_memcpy(void *d, const void *s, size_t n) {
    uint8_t *dp = (uint8_t *)d;
    const uint8_t *sp = (const uint8_t *)s;
    for (size_t i = 0; i < n; i++) dp[i] = sp[i];
}

/* ---- page size via /proc/self/auxv (AT_PAGESZ = 6), freestanding ---- */
#define SOPK_AT_PAGESZ 6
static inline size_t sopk_page_size(void) {
    long fd = sopk_syscall4(SOPK_NR_openat, -100 /*AT_FDCWD*/,
                            "/proc/self/auxv", SOPK_O_RDONLY, 0);
    size_t pg = 4096; /* safe fallback */
    if (fd < 0) return pg;
    /* auxv is an array of (type, value) longs. Scan for AT_PAGESZ. */
    long buf[64];
    for (;;) {
        long r = sopk_syscall3(SOPK_NR_read, fd, buf, (long)sizeof(buf));
        if (r <= 0) break;
        size_t cnt = (size_t)r / sizeof(long);
        for (size_t i = 0; i + 1 < cnt; i += 2) {
            if (buf[i] == SOPK_AT_PAGESZ && buf[i + 1] > 0) {
                pg = (size_t)buf[i + 1];
                sopk_syscall1(SOPK_NR_close, fd);
                return pg;
            }
            if (buf[i] == 0) { /* AT_NULL terminator */
                sopk_syscall1(SOPK_NR_close, fd);
                return pg;
            }
        }
    }
    sopk_syscall1(SOPK_NR_close, fd);
    return pg;
}

/* ---- I-cache coherency after writing code ---- */
static inline void sopk_clear_icache(void *start, void *end) {
#if defined(__aarch64__)
    /*
     * Explicit Arm ARM sequence (DDI 0487) — implemented inline rather than via
     * __builtin___clear_cache, which can lower to a libcall to __clear_cache and would
     * break the "no external symbols" property of the injected blob. Line sizes come
     * from CTR_EL0 (DminLine / IminLine, in log2 words).
     */
    uintptr_t s = (uintptr_t)start, e = (uintptr_t)end;
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    uintptr_t dline = 4u << ((ctr >> 16) & 0xf);   /* bytes per D-cache line */
    uintptr_t iline = 4u << (ctr & 0xf);           /* bytes per I-cache line */
    for (uintptr_t a = s & ~(dline - 1); a < e; a += dline)
        __asm__ volatile("dc cvau, %0" :: "r"(a) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    for (uintptr_t a = s & ~(iline - 1); a < e; a += iline)
        __asm__ volatile("ic ivau, %0" :: "r"(a) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    __asm__ volatile("isb" ::: "memory");
#elif defined(__arm__)
    /* __ARM_NR_cacheflush(start, end, flags=0) */
    sopk_syscall3(SOPK_NR_cacheflush, start, end, 0);
#else
    (void)start; (void)end; /* x86_64: coherent I-cache, nothing to do */
#endif
}

#endif /* SOPK_SYSCALLS_H */
