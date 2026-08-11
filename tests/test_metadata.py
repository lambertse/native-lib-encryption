"""decinfo layout must stay 128 bytes and survive pack/unpack unchanged (it is the
binary contract with stub/decinfo.h)."""
import os

from sopack.cipher import WHITEN_NONCE, WHITEN_SPAN, whiten, whiten_key
from sopack.metadata import DecInfo, FLAG_CHAIN_INIT, SIZE


def test_size_is_128():
    assert SIZE == 128


def test_pack_unpack_roundtrip():
    info = DecInfo(
        cipher_id=1, flags=FLAG_CHAIN_INIT,
        delta_text=-0x12345, text_size=0xABCDE,
        delta_init=0x7788, key=bytes(range(32)), nonce=bytes(range(16)),
    )
    blob = info.pack()
    assert len(blob) == 128
    back = DecInfo.unpack(blob)
    assert back.cipher_id == 1
    assert back.flags == FLAG_CHAIN_INIT
    assert back.delta_text == -0x12345
    assert back.text_size == 0xABCDE
    assert back.delta_init == 0x7788
    assert back.key == bytes(range(32))
    assert back.nonce == bytes(range(16))


def test_whiten_is_self_inverse():
    """Whitening is XOR with a keystream, so applying it twice with the same span is the
    identity - this is exactly what the injector (whiten) and the stub (de-whiten) rely on."""
    span = os.urandom(WHITEN_SPAN)
    record = os.urandom(SIZE)
    assert whiten(whiten(record, span), span) == record


def test_whiten_key_kat():
    """Pin the whiten-key derivation so an accidental change to the Python side is caught.
    The C mirror (stub/stub_cipher.h sopk_whiten_key) is locked separately by the aarch64
    dlopen integration test, which only decrypts if both sides agree byte for byte."""
    span = bytes(range(256)) * 4        # 1024 deterministic bytes
    assert whiten_key(span).hex() == (
        "ef3cacbb1efb8cf87396e014800a76a3d08bf1520a1830872e86474941ed143c")
    assert len(WHITEN_NONCE) == 16 and WHITEN_SPAN == 1024


def test_whiten_key_changes_with_span():
    """Different span bytes must yield a different key (tamper -> garbage de-whiten)."""
    base = bytes(WHITEN_SPAN)
    tampered = bytearray(base)
    tampered[0] ^= 0x01
    assert whiten_key(bytes(base)) != whiten_key(bytes(tampered))


if __name__ == "__main__":
    test_size_is_128()
    test_pack_unpack_roundtrip()
    test_whiten_is_self_inverse()
    test_whiten_key_kat()
    test_whiten_key_changes_with_span()
    print("metadata tests passed")
