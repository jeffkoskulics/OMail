"""
Passkey (WebAuthn / FIDO2) ceremonies.

Passkeys are the SOLE authentication mechanism: onboarding collects no
personal data, no email address, and no password. A user is an opaque
random handle bound to a hardware credential.

The WebAuthn PRF extension is requested during ceremonies. Its output is
evaluated inside the user's authenticator/browser and NEVER reaches the
server: the client derives an AES key from the PRF secret and encrypts the
user's asymmetric key material before uploading it as an opaque vault
blob. The host only ever stores ciphertext.
"""
import os
from typing import Iterable, List, Optional, Sequence, Tuple

from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

# The PRF evaluation salt is fixed protocol-wide; uniqueness comes from the
# per-credential PRF secret inside the authenticator.
PRF_SALT_INFO = "omail/vault-key/v1"


def new_handle() -> str:
    """Mints an opaque, zero-personal-data user handle."""
    return "user-" + os.urandom(6).hex()


class PasskeyManager:
    """Wraps python-fido2's server ceremonies for OMail's flows."""

    def __init__(
        self, rp_id: str, rp_name: str, extra_origins: Iterable[str] = ()
    ) -> None:
        self.rp_id = rp_id
        self.rp_name = rp_name
        allowed = {
            f"http://{rp_id}",
            f"https://{rp_id}",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        } | set(extra_origins)
        self._server = Fido2Server(
            PublicKeyCredentialRpEntity(id=rp_id, name=rp_name),
            verify_origin=lambda origin: origin in allowed,
        )

    # -- registration -------------------------------------------------------

    def begin_registration(self, handle: str, user_id: bytes) -> Tuple[dict, dict]:
        """Returns (JSON-safe publicKey options, ceremony state)."""
        user = PublicKeyCredentialUserEntity(
            id=user_id, name=handle, display_name=handle
        )
        options, state = self._server.register_begin(
            user,
            credentials=[],
            resident_key_requirement=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.PREFERRED,
            extensions={"prf": {}},
        )
        return dict(options), state

    def complete_registration(
        self, state: dict, response: dict
    ) -> Tuple[bytes, bytes, int]:
        """Verifies a registration response.
        Returns (credential_id, attested_credential_blob, sign_count)."""
        auth_data = self._server.register_complete(state, response)
        cred = auth_data.credential_data
        return cred.credential_id, bytes(cred), auth_data.counter

    # -- authentication -----------------------------------------------------

    def begin_authentication(self) -> Tuple[dict, dict]:
        """Starts a usernameless (discoverable credential) ceremony."""
        options, state = self._server.authenticate_begin(
            credentials=[],
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        return dict(options), state

    def complete_authentication(
        self,
        state: dict,
        response: dict,
        candidate_blobs: Sequence[bytes],
    ) -> bytes:
        """Verifies an assertion against stored credential blobs.
        Returns the matched credential id."""
        credentials: List[AttestedCredentialData] = [
            AttestedCredentialData(blob) for blob in candidate_blobs
        ]
        matched = self._server.authenticate_complete(state, credentials, response)
        return matched.credential_id
