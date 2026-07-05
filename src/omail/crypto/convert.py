"""
Ed25519 <-> X25519 key conversion.

OMail identities are Ed25519 key pairs (they double as Tor-style addresses
and signature keys). The Triple Ratchet needs Diffie-Hellman keys, so
identity keys are mapped onto Curve25519 using libsodium's birational map.
"""
import nacl.bindings as sodium
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519


def ed25519_pub_to_x25519(ed_pub: ed25519.Ed25519PublicKey) -> x25519.X25519PublicKey:
    """Converts an Ed25519 public key to the equivalent X25519 public key."""
    raw = ed_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return x25519.X25519PublicKey.from_public_bytes(
        sodium.crypto_sign_ed25519_pk_to_curve25519(raw)
    )


def ed25519_priv_to_x25519(ed_priv: ed25519.Ed25519PrivateKey) -> x25519.X25519PrivateKey:
    """Converts an Ed25519 private key to the equivalent X25519 private key."""
    seed = ed_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = ed_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # libsodium expects the 64-byte expanded secret key (seed || public)
    x_priv = sodium.crypto_sign_ed25519_sk_to_curve25519(seed + pub)
    return x25519.X25519PrivateKey.from_private_bytes(x_priv)


def x25519_pub_bytes(pub: x25519.X25519PublicKey) -> bytes:
    """Raw 32-byte encoding of an X25519 public key."""
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_priv_bytes(priv: x25519.X25519PrivateKey) -> bytes:
    """Raw 32-byte encoding of an X25519 private key."""
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
