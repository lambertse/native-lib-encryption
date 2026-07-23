"""End-to-end test for the --obfuscate / polymorphic-stub path.

Skipped unless the full obfuscation toolchain is present (aarch64 host + clang + an NDK +
the O-MVLL plugin via env), so it never blocks the pure-Python unit tests or a plain CI.
When it does run it proves the three things the feature promises:

  1. a different seed yields a structurally different stub (polymorphism),
  2. the same seed is reproducible,
  3. an O-MVLL-obfuscated stub still decrypts .text and runs (semantics preserved).
"""
import ctypes
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

_have_toolchain = bool(
    (os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT"))
    and os.environ.get("OMVLL_PLUGIN")
    and os.environ.get("OMVLL_PYTHONPATH")
)

pytestmark = pytest.mark.skipif(
    platform.machine() != "aarch64"
    or shutil.which("clang") is None
    or not _have_toolchain,
    reason="needs aarch64 host + clang + NDK/O-MVLL toolchain (ANDROID_NDK_HOME, "
           "OMVLL_PLUGIN, OMVLL_PYTHONPATH)",
)

SRC = r"""
static const char msg[] = "hello from native";
int sopk_add(int a, int b) { return a + b + 7; }
const char *sopk_msg(void) { return msg; }
__attribute__((constructor)) static void ctor(void){ volatile int x = sopk_add(1,2); (void)x; }
"""


def _build(tmp_path, seed):
    from sopack.obfuscate import build_obfuscated_stubs

    d = Path(tempfile.mkdtemp(prefix=f"stubs_{seed}_", dir=str(tmp_path)))
    used = build_obfuscated_stubs(str(d), seed=seed, logger=lambda *_: None)
    assert used == seed
    return (d / "stub_arm64-v8a.bin").read_bytes(), d


def test_seed_makes_polymorphic_but_reproducible_stub(tmp_path):
    blob_a, _ = _build(tmp_path, 1234567)
    blob_b, _ = _build(tmp_path, 987654321)
    blob_b2, _ = _build(tmp_path, 987654321)

    assert blob_a != blob_b, "different seeds must yield different stubs (polymorphism)"
    assert blob_b == blob_b2, "same seed must be reproducible"
    # The shapes really diverge, not just a few bytes.
    diff = sum(x != y for x, y in zip(blob_a, blob_b)) + abs(len(blob_a) - len(blob_b))
    assert diff > len(blob_a) // 4


def test_obfuscated_stub_still_decrypts_and_runs(tmp_path):
    from sopack.elf_inject import inject_so

    _, stub_dir = _build(tmp_path, 424242)

    src = tmp_path / "t.c"
    src.write_text(SRC)
    plain = tmp_path / "libt.so"
    subprocess.run(["clang", "-shared", "-fPIC", "-O2", "-o", str(plain), str(src)], check=True)

    enc = tmp_path / "libt.enc.so"
    inject_so(str(plain), str(enc), "arm64-v8a", cipher="chacha20", stub_dir=str(stub_dir))

    lib = ctypes.CDLL(str(enc))
    lib.sopk_msg.restype = ctypes.c_char_p
    assert lib.sopk_add(2, 3) == 12
    assert lib.sopk_msg() == b"hello from native"
    assert b"SOPK" not in enc.read_bytes()
