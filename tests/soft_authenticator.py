"""
A minimal software passkey for tests.

Emulates the parts of a WebAuthn authenticator that OMail's ceremonies
exercise: 'none'-attestation registration and assertion signing with an
ES256 credential, in WebAuthn Level 3 JSON wire format.
"""
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.utils import websafe_decode, websafe_encode


class SoftAuthenticator:
    def __init__(self, rp_id: str, origin: str):
        self.rp_id = rp_id
        self.origin = origin
        self.credential_id = os.urandom(32)
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.sign_count = 0
        self.user_handle = None

    # flags: UP (0x01) | UV (0x04) | AT (0x40) when attested data present
    def _auth_data(self, with_credential: bool) -> bytes:
        rp_id_hash = hashlib.sha256(self.rp_id.encode()).digest()
        flags = 0x01 | 0x04 | (0x40 if with_credential else 0x00)
        data = rp_id_hash + bytes([flags]) + self.sign_count.to_bytes(4, "big")
        if with_credential:
            cose_key = cbor.encode(dict(ES256.from_cryptography_key(self.private_key.public_key())))
            data += (
                bytes(16)  # AAGUID
                + len(self.credential_id).to_bytes(2, "big")
                + self.credential_id
                + cose_key
            )
        return data

    def _client_data(self, ceremony_type: str, challenge_b64url: str) -> bytes:
        return json.dumps(
            {
                "type": ceremony_type,
                "challenge": challenge_b64url,
                "origin": self.origin,
                "crossOrigin": False,
            }
        ).encode()

    def create(self, public_key_options: dict) -> dict:
        """Answers a registration ceremony (navigator.credentials.create)."""
        pk = public_key_options["publicKey"]
        self.user_handle = websafe_decode(pk["user"]["id"])
        client_data = self._client_data("webauthn.create", pk["challenge"])
        att_obj = cbor.encode(
            {"fmt": "none", "attStmt": {}, "authData": self._auth_data(True)}
        )
        return {
            "id": websafe_encode(self.credential_id),
            "rawId": websafe_encode(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": websafe_encode(client_data),
                "attestationObject": websafe_encode(att_obj),
            },
            "clientExtensionResults": {"prf": {"enabled": True}},
        }

    def get(self, public_key_options: dict) -> dict:
        """Answers an authentication ceremony (navigator.credentials.get)."""
        pk = public_key_options["publicKey"]
        self.sign_count += 1
        auth_data = self._auth_data(False)
        client_data = self._client_data("webauthn.get", pk["challenge"])
        signature = self.private_key.sign(
            auth_data + hashlib.sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        return {
            "id": websafe_encode(self.credential_id),
            "rawId": websafe_encode(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": websafe_encode(client_data),
                "authenticatorData": websafe_encode(auth_data),
                "signature": websafe_encode(signature),
                "userHandle": websafe_encode(self.user_handle) if self.user_handle else None,
            },
            "clientExtensionResults": {"prf": {"results": {"first": websafe_encode(os.urandom(32))}}},
        }
