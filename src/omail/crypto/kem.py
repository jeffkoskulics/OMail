"""
Key Encapsulation Mechanism (KEM) abstraction for the Triple Ratchet.

The third ratchet mixes a KEM shared secret into every DH ratchet step,
providing post-compromise security against harvest-now/decrypt-later
quantum adversaries. Two interchangeable KEMs are provided:

  - ML-KEM-768 (FIPS 203): the post-quantum default, via kyber-py.
  - X25519-KEM: a classical DH-based KEM used when a peer (for example a
    constrained browser client) cannot run ML-KEM. The ratchet structure
    is identical; only the encapsulation primitive changes.

Both peers of a session must agree on the KEM algorithm at session
initiation; the algorithm name travels in the handshake blob.
"""
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import x25519
from kyber_py.ml_kem import ML_KEM_768

from omail.crypto.convert import x25519_priv_bytes, x25519_pub_bytes

ML_KEM_768_NAME = "ML-KEM-768"
X25519_KEM_NAME = "X25519"


class MLKEM768:
    """FIPS 203 ML-KEM-768 (post-quantum lattice KEM)."""

    name = ML_KEM_768_NAME

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """Returns (encapsulation_key, decapsulation_key)."""
        ek, dk = ML_KEM_768.keygen()
        return ek, dk

    @staticmethod
    def encaps(public_key: bytes) -> Tuple[bytes, bytes]:
        """Returns (ciphertext, shared_secret)."""
        shared_secret, ciphertext = ML_KEM_768.encaps(public_key)
        return ciphertext, shared_secret

    @staticmethod
    def decaps(private_key: bytes, ciphertext: bytes) -> bytes:
        return ML_KEM_768.decaps(private_key, ciphertext)


class X25519KEM:
    """Classical ECDH-based KEM (ephemeral X25519, hashed shared point)."""

    name = X25519_KEM_NAME

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        priv = x25519.X25519PrivateKey.generate()
        return x25519_pub_bytes(priv.public_key()), x25519_priv_bytes(priv)

    @staticmethod
    def encaps(public_key: bytes) -> Tuple[bytes, bytes]:
        eph = x25519.X25519PrivateKey.generate()
        eph_pub = x25519_pub_bytes(eph.public_key())
        dh = eph.exchange(x25519.X25519PublicKey.from_public_bytes(public_key))
        shared_secret = hashlib.sha256(dh + eph_pub + public_key).digest()
        return eph_pub, shared_secret

    @staticmethod
    def decaps(private_key: bytes, ciphertext: bytes) -> bytes:
        priv = x25519.X25519PrivateKey.from_private_bytes(private_key)
        public_key = x25519_pub_bytes(priv.public_key())
        dh = priv.exchange(x25519.X25519PublicKey.from_public_bytes(ciphertext))
        return hashlib.sha256(dh + ciphertext + public_key).digest()


_KEMS = {MLKEM768.name: MLKEM768, X25519KEM.name: X25519KEM}


def get_kem(name: str):
    """Looks up a KEM implementation by its wire-format name."""
    try:
        return _KEMS[name]
    except KeyError:
        raise ValueError(f"Unknown KEM algorithm: {name!r}") from None
