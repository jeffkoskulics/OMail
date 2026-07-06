"""
User Privacy Addresses (UPAs). See docs/concepts.md for the full model.

A UPA is a *per-relationship inbound address* with the form:

    <host-onion-address>.onion/<relationship-address>

where <relationship-address> is a key encoded exactly like a Tor v3 onion
address (base32 of pubkey || checksum || version) but without the ".onion"
suffix.

A UPA always lives on the host of the party that *receives* on it, and is
reserved for exactly one correspondent: a user mints a distinct UPA per
relationship rather than publishing one static address. There are no
memorable, guessable, or enumerable addresses — possession of a UPA is the
only way to route to that relationship's inbox.

This module handles the encoding/derivation/parsing of the address itself;
the allocation of per-relationship keys lives in the host/DB layer.
"""
import base64
import hashlib
import re
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

_ONION_VERSION = b"\x03"
_B32_RE = re.compile(r"^[a-z2-7]{56}$")


def _checksum(pub_bytes: bytes) -> bytes:
    return hashlib.sha3_256(
        b".onion checksum" + pub_bytes + _ONION_VERSION
    ).digest()[:2]


def encode_pubkey(pub_bytes: bytes) -> str:
    """Encodes a raw 32-byte Ed25519 public key in Tor v3 onion style
    (56 lowercase base32 characters, no ".onion" suffix)."""
    if len(pub_bytes) != 32:
        raise ValueError("Expected a raw 32-byte Ed25519 public key")
    combined = pub_bytes + _checksum(pub_bytes) + _ONION_VERSION
    return base64.b32encode(combined).decode("ascii").lower()


def decode_pubkey(encoded: str) -> bytes:
    """Decodes and verifies an onion-style address back to the raw
    32-byte Ed25519 public key. Raises ValueError on bad input."""
    encoded = encoded.strip().lower()
    if not _B32_RE.match(encoded):
        raise ValueError("Malformed address: expected 56 base32 characters")
    combined = base64.b32decode(encoded.upper())
    pub_bytes, checksum, version = combined[:32], combined[32:34], combined[34:]
    if version != _ONION_VERSION:
        raise ValueError("Unsupported address version")
    if checksum != _checksum(pub_bytes):
        raise ValueError("Address checksum mismatch")
    return pub_bytes


def onion_address(public_key: ed25519.Ed25519PublicKey) -> str:
    """Derives the Tor v3 .onion address for an Ed25519 public key."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return encode_pubkey(raw) + ".onion"


def derive_upa(host_onion: str, user_pub_bytes: bytes) -> str:
    """Builds a User Privacy Address from the host .onion address and the
    user's raw Ed25519 public key."""
    host_onion = host_onion.strip().lower()
    if not host_onion.endswith(".onion"):
        host_onion += ".onion"
    if not _B32_RE.match(host_onion[: -len(".onion")]):
        raise ValueError(f"Malformed host onion address: {host_onion!r}")
    return f"{host_onion}/{encode_pubkey(user_pub_bytes)}"


def parse_upa(upa: str) -> Tuple[str, bytes]:
    """Splits and validates a UPA. Returns (host_onion, user_pub_bytes)."""
    upa = upa.strip().lower()
    host, sep, user = upa.partition("/")
    if not sep or not host.endswith(".onion"):
        raise ValueError("Malformed UPA: expected <host>.onion/<user-address>")
    if not _B32_RE.match(host[: -len(".onion")]):
        raise ValueError("Malformed UPA host onion address")
    return host, decode_pubkey(user)
