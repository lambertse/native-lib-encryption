"""End-to-end injection + runtime test.

On an aarch64 Linux host with clang and the prebuilt arm64 stub available, this:
  1. compiles a tiny shared library,
  2. injects it (encrypt .text + stub) with the real injector,
  3. dlopen()s the injected library and asserts the stub decrypted .text at load
     and the code (including a .rodata reference) runs correctly.

It is skipped when the toolchain/stub/arch isn't present (e.g. CI without clang, or a
non-aarch64 host), so it never blocks the pure-Python unit tests.

The stub uses only standard Linux syscalls, so a green run here validates the whole
runtime mechanism (mmap → decrypt → mremap-onto-original-base → mprotect → cache flush)
on real ARM64 hardware — everything except Android's SELinux execmem policy.
"""
import ctypes
import os
import platform
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

STUB = os.path.join(ROOT, "sopack", "stubs", "stub_arm64-v8a.bin")

pytestmark = pytest.mark.skipif(
    platform.machine() != "aarch64"
    or shutil.which("clang") is None
    or not os.path.exists(STUB),
    reason="needs aarch64 host + clang + prebuilt arm64 stub",
)

SRC = r"""
static const char msg[] = "hello from native";
int sopk_add(int a, int b) { return a + b + 7; }
const char *sopk_msg(void) { return msg; }
__attribute__((constructor)) static void ctor(void){ volatile int x = sopk_add(1,2); (void)x; }
"""


def test_inject_and_run(tmp_path):
    from sopack.elf_inject import inject_so

    src = tmp_path / "t.c"
    src.write_text(SRC)
    plain = tmp_path / "libt.so"
    subprocess.run(["clang", "-shared", "-fPIC", "-O2", "-o", str(plain), str(src)],
                   check=True)

    enc = tmp_path / "libt.enc.so"
    r = inject_so(str(plain), str(enc), "arm64-v8a", cipher="chacha20")
    assert r.strategy.startswith("DT_INIT")

    # dlopen -> DT_INIT runs the stub -> .text is decrypted in place
    lib = ctypes.CDLL(str(enc))
    lib.sopk_msg.restype = ctypes.c_char_p
    assert lib.sopk_add(2, 3) == 12
    assert lib.sopk_add(100, 200) == 307
    assert lib.sopk_msg() == b"hello from native"   # .rodata ref resolves correctly


def test_xor_cipher_also_runs(tmp_path):
    from sopack.elf_inject import inject_so

    src = tmp_path / "t.c"
    src.write_text(SRC)
    plain = tmp_path / "libt.so"
    subprocess.run(["clang", "-shared", "-fPIC", "-O2", "-o", str(plain), str(src)],
                   check=True)
    enc = tmp_path / "libt.xor.so"
    inject_so(str(plain), str(enc), "arm64-v8a", cipher="xor")
    lib = ctypes.CDLL(str(enc))
    assert lib.sopk_add(2, 3) == 12


def test_no_init_lib_uses_inplace_dtinit(tmp_path):
    """A library with no DT_INIT / DT_INIT_ARRAY (like Flutter's libapp.so) must get a
    DT_INIT added in place (DT_NULL terminator overwrite) and still decrypt + run."""
    from sopack.elf_inject import inject_so

    # no constructor (would create DT_INIT_ARRAY) + -nostartfiles (no crti _init)
    # => a library with no init hook at all, forcing the in-place DT_INIT path.
    src = tmp_path / "t.c"
    src.write_text(
        'static const char msg[] = "hello from native";\n'
        "int sopk_add(int a,int b){return a+b+7;}\n"
        "const char *sopk_msg(void){return msg;}\n"
    )
    plain = tmp_path / "libni.so"
    subprocess.run(["clang", "-shared", "-fPIC", "-O2", "-nostartfiles",
                    "-o", str(plain), str(src)], check=True)
    enc = tmp_path / "libni.enc.so"
    r = inject_so(str(plain), str(enc), "arm64-v8a", cipher="chacha20")
    assert r.strategy == "DT_INIT-inplace"
    lib = ctypes.CDLL(str(enc))
    lib.sopk_msg.restype = ctypes.c_char_p
    assert lib.sopk_add(2, 3) == 12
    assert lib.sopk_msg() == b"hello from native"
