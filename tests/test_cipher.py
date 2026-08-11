"""Validate the ChaCha20 implementation against the RFC 8439 §2.4.2 test vector.
If this passes, the desktop cipher matches the reference; the C stub mirrors this code
line for line, so the round-trip (encrypt on desktop, decrypt on device) is correct.

Run: python -m pytest tests/  (or: python tests/test_cipher.py)
"""
import os
import shutil
import struct

import pytest

from sopack import cipher
from sopack.cipher import CIPHER_CHACHA20, CIPHER_XOR, apply_cipher


def test_chacha20_rfc8439_vector():
    key = bytes(range(32))                       # 00 01 .. 1f
    nonce = bytes.fromhex("000000000000004a00000000")  # 12-byte nonce
    counter = 1
    nonce16 = nonce + struct.pack("<I", counter)  # our layout: nonce||counter

    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    )
    ct = apply_cipher(CIPHER_CHACHA20, plaintext, key, nonce16)
    assert ct == expected, "ChaCha20 keystream mismatch vs RFC 8439"

    # round-trip
    assert apply_cipher(CIPHER_CHACHA20, ct, key, nonce16) == plaintext


def test_xor_roundtrip():
    key = bytes(range(32))
    data = b"the quick brown fox" * 7
    enc = apply_cipher(CIPHER_XOR, data, key, b"\x00" * 16)
    assert apply_cipher(CIPHER_XOR, enc, key, b"\x00" * 16) == data


# ---- wbaes: AES-128-CTR must stay bit-exact with the white-box KEY WRAP ---------------
# Since wbcrypto 2.0.0 the white-box never touches `.text`; it only wraps a 32-byte session
# key, and wbc_wrap_key is plain CTR under the sealed key. So the pack host builds the wrap
# itself with cipher.aes128_ctr. These KATs pin that contract - if they drift, the device
# unwraps a garbage session key and the app runs encrypted code.
_AES_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def test_aes128_fips197_ecb_block():
    """AES core vs FIPS-197 - the vector `wb_encrypt` self-checks (proves white-box==AES)."""
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    rk = cipher._aes128_key_schedule(_AES_KEY)
    ct = cipher._aes128_encrypt_block(pt, rk)
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_aes128_ctr_is_the_whitebox_key_wrap():
    """THE authoritative anchor: captured from the real wbcrypto 2.0.0 `wbc_unwrap_key`.

    A blob was sealed with kek=000102..0f, then wbc_unwrap_key was called on the 48-byte
    input `iv || 00 01 .. 1f`. CTR is its own inverse, so its output is exactly
    aes128_ctr(00..1f, kek, iv) - i.e. what the pack host must produce for `wrapped`.
    The first 16 bytes are visibly the FIPS-197 vector XOR'd with the input, which is the
    same fact from the other direction."""
    iv = bytes.fromhex("00112233445566778899aabbccddeeff")
    sk = bytes(range(32))                                     # exactly WBC_SESSION_KEY_BYTES
    exp = ("69c5e2db6e7e0237d0c4bd8b7cb9cb55"
           "cd69952ebe4891effc8ea4ee5d03d02d")
    assert cipher._aes128_ctr_py(sk, _AES_KEY, iv).hex() == exp
    assert cipher.aes128_ctr(sk, _AES_KEY, iv).hex() == exp   # openssl fast-path (if present)
    # and the wrap is self-inverse, which is why the device needs no separate unwrap key
    assert cipher.aes128_ctr(cipher.aes128_ctr(sk, _AES_KEY, iv), _AES_KEY, iv) == sk


def test_aes128_ctr_partial_final_block_vector():
    """Legacy vector, kept as a plain AES-128-CTR KAT: it pins the partial-final-block and
    big-endian-carry behaviour over 40 bytes. (It was captured from wbc_crypt_ctr, which
    2.0.0 deleted, so it no longer corresponds to any callable SDK entry point.)"""
    iv = bytes.fromhex("00112233445566778899aabbccddeeff")
    pt = b"sopack .text white-box CTR probe vector!"          # 40 bytes, incl. partial block
    exp = ("1aab90b90910241eaca8cff450c3ad33a91daa5fc525a7bbb0c"
           "59e853371ac57b60676dc6f7e1e6c")
    assert cipher._aes128_ctr_py(pt, _AES_KEY, iv).hex() == exp
    assert cipher.aes128_ctr(pt, _AES_KEY, iv).hex() == exp


def test_aes128_ctr_openssl_matches_python_across_carry():
    """Any openssl fast-path must equal the pure-Python reference over many blocks + carry."""
    data = os.urandom(4096 + 7)
    _kek, _sk, wrap_iv, _nonce = cipher.gen_wbaes_params()
    key = os.urandom(16)
    assert cipher._aes128_ctr_py(data, key, wrap_iv) == cipher.aes128_ctr(data, key, wrap_iv)


def test_gen_wbaes_params_shapes():
    """provision.provision_text unpacks these four in order; lengths are load-bearing."""
    kek, sk, wrap_iv, nonce16 = cipher.gen_wbaes_params()
    assert (len(kek), len(sk), len(wrap_iv), len(nonce16)) == (16, 32, 16, 16)
    assert len(sk) == cipher.SESSION_KEY_BYTES
    assert nonce16[12:] == b"\x00\x00\x00\x00"      # ChaCha20 initial counter is zero
    assert len(wrap_iv + cipher.aes128_ctr(sk, kek, wrap_iv)) == cipher.WRAPPED_KEY_BYTES


# ---- ChaCha20 openssl fast path (the bulk cipher for wbaes and --cipher chacha20) ------
def test_chacha20_openssl_matches_python_above_and_below_threshold():
    """`.text` is multi-MB on real libs and pure Python runs at ~0.6 MB/s, so apply_cipher
    shells out to openssl past a size threshold. The two paths MUST agree byte for byte -
    a mismatch means every packed lib decrypts to garbage on device."""
    key = os.urandom(32)
    nonce16 = os.urandom(12) + bytes([7, 0, 0, 0])       # non-zero initial counter too
    for n in (1024, cipher._OPENSSL_MIN + 7, 3 * cipher._OPENSSL_MIN):
        data = os.urandom(n)
        buf = bytearray(data)
        cipher._chacha20_apply(buf, key, nonce16)
        assert apply_cipher(CIPHER_CHACHA20, data, key, nonce16) == bytes(buf), f"n={n}"


def test_openssl_fastpath_rejects_a_wrong_iv_convention(tmp_path, monkeypatch):
    """The dangerous failure mode: an `openssl` whose 16-byte ChaCha20 IV convention differs
    from ours returns the SAME LENGTH with wrong bytes. A length-only guard would accept it,
    ship a corrupt `.text` that self-verify cannot detect, and crash only on device. The pack
    host's openssl is not one implementation (macOS = LibreSSL, Linux = OpenSSL 3.x), so this
    must be caught by comparing against the pure-Python reference."""
    if shutil.which("openssl") is None:
        pytest.skip("no system openssl to build the stand-in from")
    fake = tmp_path / "fake-openssl"
    # Accepts our arguments, swaps the IV halves (i.e. the original counter(8)||nonce(8)
    # layout instead of openssl's counter(4,LE)||nonce(12)), same output length.
    fake.write_text(
        '#!/bin/sh\n'
        'while [ $# -gt 0 ]; do\n'
        '  case "$1" in -K) K="$2"; shift 2;; -iv) IV="$2"; shift 2;; *) shift;; esac\n'
        'done\n'
        'IV2="$(printf %s "$IV" | cut -c25-32)$(printf %s "$IV" | cut -c1-24)"\n'
        'exec openssl enc -chacha20 -K "$K" -iv "$IV2"\n')
    fake.chmod(0o755)

    real_which = shutil.which
    monkeypatch.setattr(cipher.shutil, "which",
                        lambda n: str(fake) if n == "openssl" else real_which(n))

    data = os.urandom(cipher._OPENSSL_MIN + 512)
    key = os.urandom(32)
    nonce16 = os.urandom(12) + bytes([4, 0, 0, 0])
    expect = bytearray(data)
    cipher._chacha20_apply(expect, key, nonce16)

    # the fast path must refuse the wrong-convention output...
    assert cipher._chacha20_openssl(data, key, nonce16) is None
    # ...and apply_cipher must still return the correct bytes via the pure-Python fallback.
    assert apply_cipher(CIPHER_CHACHA20, data, key, nonce16) == bytes(expect)


def test_chacha20_openssl_helper_directly():
    """Exercise the fast path even when apply_cipher would take the pure-Python branch, so
    the IV-half-swap (openssl wants counter||nonce, we store nonce||counter) is pinned."""
    key = os.urandom(32)
    nonce16 = os.urandom(12) + bytes([2, 0, 0, 0])
    data = os.urandom(200)
    fast = cipher._chacha20_openssl(data, key, nonce16)
    if fast is None:
        pytest.skip("no usable system openssl")
    buf = bytearray(data)
    cipher._chacha20_apply(buf, key, nonce16)
    assert fast == bytes(buf)


def test_whiten_pass_self_inverse():
    blob = os.urandom(2048)
    w = cipher.whiten_pass(b"integration-demo", blob)
    assert w != b"integration-demo"
    assert cipher.whiten_pass(w, blob) == b"integration-demo"


if __name__ == "__main__":
    test_chacha20_rfc8439_vector()
    test_xor_roundtrip()
    test_aes128_fips197_ecb_block()
    test_aes128_ctr_is_the_whitebox_key_wrap()
    test_aes128_ctr_partial_final_block_vector()
    test_aes128_ctr_openssl_matches_python_across_carry()
    test_gen_wbaes_params_shapes()
    test_chacha20_openssl_matches_python_above_and_below_threshold()
    test_whiten_pass_self_inverse()
    print("cipher tests passed")
