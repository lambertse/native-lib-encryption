"""Validate the ChaCha20 implementation against the RFC 8439 §2.4.2 test vector.
If this passes, the desktop cipher matches the reference; the C stub mirrors this code
line for line, so the round-trip (encrypt on desktop, decrypt on device) is correct.

Run: python -m pytest tests/  (or: python tests/test_cipher.py)
"""
import struct

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


if __name__ == "__main__":
    test_chacha20_rfc8439_vector()
    test_xor_roundtrip()
    print("cipher tests passed")
