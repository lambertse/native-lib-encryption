/*
 * mini_arm64.c - source for tests/fixtures/mini_arm64.so, a tiny aarch64 shared
 * object used by tests/test_wbaes.py as BOTH the injection target and the mock
 * helper skeleton.
 *
 * Regenerate (on any aarch64 host, or with an aarch64 cross-compiler):
 *
 *   cc -shared -nostdlib -fPIC -O2 -Wl,-z,max-page-size=16384 \
 *      -Wl,-soname,libmini_arm64.so tests/fixtures/mini_arm64.c \
 *      -o tests/fixtures/mini_arm64.so
 *
 * Three properties are deliberate, and a replacement fixture must keep all
 * three or the tests silently stop testing what they claim to:
 *
 *  1. NO DT_NEEDED (`-nostdlib`). `_emit_helper` rejects a skeleton whose
 * dependencies are not bionic, and an empty set passes - which lets one file
 * serve as target and skeleton.
 *
 *  2. Exported symbol names whose ALPHABETICAL order differs from their order
 * in `.dynstr`. LIEF re-sorts `.dynstr` when it writes, so this is what makes a
 * desynchronised string table observable: with an already-sorted table every
 * offset would still land on the right name and the regression would pass
 * unnoticed. Hence the zzz_/mmm_/aaa_ naming.
 *
 *  3. A `.text` larger than 16 KB, so the decrypt spans more than one
 * max-page-size page and the page-window arithmetic in stub/sopk_rt.c is
 * actually exercised.
 */

/* Property 3: pad .text past 16 KB. 0x1f fills with a recognisable non-zero
 * byte, so a failure to decrypt is obvious in a hex dump rather than looking
 * like a hole. */
__asm__(".text\n\t.balign 4\n\t.space 40960, 0x1f\n");

/* Property 2: defined in an order that is NOT alphabetical. */
int zzz_first_in_file(int x);
int mmm_second_in_file(int x);
int aaa_third_in_file(int x);

int zzz_first_in_file(int x) { return x * 3 + 1; }
int mmm_second_in_file(int x) { return zzz_first_in_file(x) ^ 0x5a; }
int aaa_third_in_file(int x) { return mmm_second_in_file(x) + 7; }
