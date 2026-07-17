"""decinfo layout must stay 128 bytes and survive pack/unpack unchanged (it is the
binary contract with stub/decinfo.h)."""
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


if __name__ == "__main__":
    test_size_is_128()
    test_pack_unpack_roundtrip()
    print("metadata tests passed")
