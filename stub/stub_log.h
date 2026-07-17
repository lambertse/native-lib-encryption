/*
 * stub_log.h — optional logcat confirmation, written straight to Android's logd
 * socket (/dev/socket/logdw) using the liblog wire format. Freestanding: raw syscalls
 * only, no liblog/libc dependency. Apps are permitted to write logd (that is how all
 * app logging works), so this produces a normal logcat line under untrusted_app.
 *
 * Enabled per-injection via SOPK_FLAG_LOG in decinfo.flags (CLI: --log). When off, the
 * code is compiled in but never called, so it is invisible.
 *
 * Wire format of one datagram to logdw:
 *   [id:u8=LOG_ID_MAIN][tid:u16][tv_sec:u32][tv_nsec:u32][prio:u8][tag\0][msg\0]
 */
#ifndef SOPK_LOG_H
#define SOPK_LOG_H

#include "syscalls.h"

#if defined(__aarch64__)
#  define SOPK_NR_socket        198
#  define SOPK_NR_connect       203
#  define SOPK_NR_gettid        178
#  define SOPK_NR_clock_gettime 113
#elif defined(__x86_64__)
#  define SOPK_NR_socket        41
#  define SOPK_NR_connect       42
#  define SOPK_NR_gettid        186
#  define SOPK_NR_clock_gettime 228
#elif defined(__arm__)
#  define SOPK_NR_socket        281
#  define SOPK_NR_connect       283
#  define SOPK_NR_gettid        224
#  define SOPK_NR_clock_gettime 263
#endif

#define SOPK_AF_UNIX     1
#define SOPK_SOCK_DGRAM  2
#define SOPK_LOG_ID_MAIN 0
#define SOPK_LOG_INFO    4

/* logd socket path — overridable at build time for testing against a local socket. */
#ifndef SOPK_LOGD_PATH
#  define SOPK_LOGD_PATH "/dev/socket/logdw"
#endif

/* Emit one INFO logcat line with the given tag + message. Best-effort; silent on any
 * error so it can never destabilise the host process. */
static inline void sopk_logcat(const char *tag, const char *msg) {
    long fd = sopk_syscall3(SOPK_NR_socket, SOPK_AF_UNIX, SOPK_SOCK_DGRAM, 0);
    if (fd < 0) return;

    struct { unsigned short family; char path[108]; } addr;
    addr.family = SOPK_AF_UNIX;
    const char *p = SOPK_LOGD_PATH;
    int pl = 0;
    for (; p[pl]; pl++) addr.path[pl] = p[pl];
    addr.path[pl] = 0;
    if (sopk_syscall3(SOPK_NR_connect, fd, &addr, (long)(2 + pl + 1)) < 0) {
        sopk_syscall1(SOPK_NR_close, fd);
        return;
    }

    long ts[2] = {0, 0};
    sopk_syscall2(SOPK_NR_clock_gettime, 0 /*CLOCK_REALTIME*/, ts);
    long tid = sopk_syscall0(SOPK_NR_gettid);

    unsigned char b[256];
    int o = 0;
    b[o++] = SOPK_LOG_ID_MAIN;
    b[o++] = (unsigned char)(tid & 0xff);
    b[o++] = (unsigned char)((tid >> 8) & 0xff);
    unsigned int sec = (unsigned int)ts[0], nsec = (unsigned int)ts[1];
    b[o++] = sec & 0xff;  b[o++] = (sec >> 8) & 0xff;
    b[o++] = (sec >> 16) & 0xff; b[o++] = (sec >> 24) & 0xff;
    b[o++] = nsec & 0xff; b[o++] = (nsec >> 8) & 0xff;
    b[o++] = (nsec >> 16) & 0xff; b[o++] = (nsec >> 24) & 0xff;
    b[o++] = SOPK_LOG_INFO;
    for (int k = 0; tag[k] && o < 200; k++) b[o++] = (unsigned char)tag[k];
    b[o++] = 0;
    for (int k = 0; msg[k] && o < 250; k++) b[o++] = (unsigned char)msg[k];
    b[o++] = 0;

    sopk_syscall3(SOPK_NR_write, fd, b, o);
    sopk_syscall1(SOPK_NR_close, fd);
}

/* Log "<prefix>0x<hex64>" — used to report stage + address/errno while debugging. */
static inline void sopk_logv(const char *tag, const char *prefix, unsigned long v) {
    char msg[96];
    int o = 0;
    for (int k = 0; prefix[k] && o < 60; k++) msg[o++] = prefix[k];
    msg[o++] = '0'; msg[o++] = 'x';
    for (int i = 0; i < 16; i++) {
        int nib = (int)((v >> ((15 - i) * 4)) & 0xf);
        msg[o++] = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10);
    }
    msg[o] = 0;
    sopk_logcat(tag, msg);
}

#endif /* SOPK_LOG_H */
