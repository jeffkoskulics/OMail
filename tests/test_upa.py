import pytest
from cryptography.hazmat.primitives import serialization

from omail.key_pair import KeyPair
from omail.upa import (
    decode_pubkey,
    derive_upa,
    encode_pubkey,
    onion_address,
    parse_upa,
)


@pytest.fixture
def user_pub_bytes():
    kp = KeyPair()
    kp.generate_key_pair()
    return kp.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


@pytest.fixture
def host_onion():
    kp = KeyPair()
    kp.generate_key_pair()
    return onion_address(kp.public_key)


def test_encode_decode_roundtrip(user_pub_bytes):
    encoded = encode_pubkey(user_pub_bytes)
    assert len(encoded) == 56
    assert encoded == encoded.lower()
    assert decode_pubkey(encoded) == user_pub_bytes


def test_encode_rejects_bad_length():
    with pytest.raises(ValueError, match="32-byte"):
        encode_pubkey(b"short")


def test_decode_rejects_malformed():
    with pytest.raises(ValueError, match="56 base32"):
        decode_pubkey("not-an-address")


def test_decode_rejects_corrupted_checksum(user_pub_bytes):
    encoded = encode_pubkey(user_pub_bytes)
    # Flip a character in the key portion (first 52 chars cover the pubkey)
    flipped = ("a" if encoded[10] != "a" else "b")
    corrupted = encoded[:10] + flipped + encoded[11:]
    with pytest.raises(ValueError):
        decode_pubkey(corrupted)


def test_onion_address_shape(host_onion):
    assert host_onion.endswith(".onion")
    assert len(host_onion) == 56 + len(".onion")


def test_derive_and_parse_upa(host_onion, user_pub_bytes):
    upa = derive_upa(host_onion, user_pub_bytes)
    assert upa == f"{host_onion}/{encode_pubkey(user_pub_bytes)}"
    parsed_host, parsed_pub = parse_upa(upa)
    assert parsed_host == host_onion
    assert parsed_pub == user_pub_bytes


def test_derive_upa_appends_onion_suffix(host_onion, user_pub_bytes):
    bare = host_onion[: -len(".onion")]
    assert derive_upa(bare, user_pub_bytes) == derive_upa(host_onion, user_pub_bytes)


def test_derive_upa_rejects_bad_host(user_pub_bytes):
    with pytest.raises(ValueError, match="host onion"):
        derive_upa("example.com", user_pub_bytes)


def test_parse_upa_rejects_missing_separator(host_onion):
    with pytest.raises(ValueError, match="Malformed UPA"):
        parse_upa(host_onion)


def test_parse_upa_rejects_clearnet_host(user_pub_bytes):
    with pytest.raises(ValueError):
        parse_upa(f"mail.example.com/{encode_pubkey(user_pub_bytes)}")
