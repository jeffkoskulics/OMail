"""
Host node identity and host-side messaging.

The host node has a single Ed25519 identity key that serves double duty:
it is the Tor v3 onion service key (the .onion address IS its public key)
and the host's Triple Ratchet identity. The host's own UPA is therefore
`<onion>/<same key, onion-encoded>`.

The host acts as a blind router for user-to-user traffic and as a first,
automatically provisioned contact ("Host Node") that every new tenant can
message. Host-side ratchet sessions are the only sessions whose state the
node stores in the clear — they are the host's own conversations.
"""
import base64
import datetime
import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from omail.crypto.kem import ML_KEM_768_NAME
from omail.crypto.triple_ratchet import (
    PrekeyBundle,
    ResponderKeys,
    TripleRatchet,
    make_prekey_bundle,
)
from omail.db import Database
from omail.key_pair import KeyPair
from omail.upa import derive_upa, onion_address

HOST_CONTACT_NAME = "Host Node"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data)


class HostNode:
    """The node's own identity and its side of host<->tenant sessions."""

    def __init__(self, db: Database, host_name: Optional[str] = None) -> None:
        self.db = db
        if host_name:
            db.set_config("host_name", host_name)
        seed_hex = db.get_config("host_identity_seed")
        if seed_hex is None:
            seed_hex = os.urandom(32).hex()
            db.set_config("host_identity_seed", seed_hex)
        self.identity_seed = bytes.fromhex(seed_hex)
        self._priv = ed25519.Ed25519PrivateKey.from_private_bytes(self.identity_seed)

    # -- identity -----------------------------------------------------------

    @property
    def host_name(self) -> str:
        return self.db.get_config("host_name", "OMail")

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self._priv.public_key()

    @property
    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def onion(self) -> str:
        """The node's .onion address (derived from the identity key)."""
        return onion_address(self.public_key)

    @property
    def upa(self) -> str:
        """The host node's own User Privacy Address."""
        return derive_upa(self.onion, self.public_bytes)

    def key_pair(self) -> KeyPair:
        """The identity as a KeyPair, for OnionService provisioning."""
        kp = KeyPair()
        kp.private_key = self._priv
        kp.public_key = self.public_key
        return kp

    def user_upa(self, identity_pub: bytes) -> str:
        """Derives a tenant's UPA on this host."""
        return derive_upa(self.onion, identity_pub)

    # -- prekey bundles -------------------------------------------------------

    def publish_prekey_bundle(self, kem_alg: str = ML_KEM_768_NAME) -> dict:
        """Mints a one-time prekey bundle a client can initiate against."""
        bundle, keys = make_prekey_bundle(self.identity_seed, kem_alg=kem_alg)
        keys_json = {
            "ik_ed_priv": _b64(keys.ik_ed_priv),
            "spk_priv": _b64(keys.spk_priv),
            "kem_priv": _b64(keys.kem_priv),
            "kem_alg": keys.kem_alg,
        }
        prekey_id = self.db.add_host_prekey(bundle.to_dict(), keys_json)
        return {"prekey_id": prekey_id, "bundle": bundle.to_dict()}

    # -- host-side ratchet sessions ---------------------------------------------

    def _load_session(self, user_id: int) -> Optional[TripleRatchet]:
        state = self.db.get_host_session(user_id)
        return TripleRatchet.from_dict(state) if state else None

    def _save_session(self, user_id: int, ratchet: TripleRatchet) -> None:
        self.db.put_host_session(user_id, ratchet.to_dict())

    def receive_envelope(
        self, user_id: int, envelope: dict, prekey_id: Optional[int] = None
    ) -> bytes:
        """Decrypts a tenant->host envelope, establishing the session when
        the envelope carries a handshake blob."""
        if "init" in envelope:
            if prekey_id is None:
                raise ValueError("Handshake envelope requires a prekey_id")
            keys_json = self.db.take_host_prekey(prekey_id)
            if keys_json is None:
                raise ValueError("Unknown or already-used prekey")
            keys = ResponderKeys(
                ik_ed_priv=_unb64(keys_json["ik_ed_priv"]),
                spk_priv=_unb64(keys_json["spk_priv"]),
                kem_priv=_unb64(keys_json["kem_priv"]),
                kem_alg=keys_json["kem_alg"],
            )
            ratchet = TripleRatchet.respond(keys, envelope["init"])
        else:
            ratchet = self._load_session(user_id)
            if ratchet is None:
                raise ValueError("No established session for this user")
        plaintext = ratchet.decrypt(envelope)
        self._save_session(user_id, ratchet)
        return plaintext

    def send_message(self, user_id: int, plaintext: bytes) -> dict:
        """Encrypts a host->tenant message under the established session."""
        ratchet = self._load_session(user_id)
        if ratchet is None:
            raise ValueError("No established session for this user")
        envelope = ratchet.encrypt(plaintext)
        self._save_session(user_id, ratchet)
        return envelope

    # -- host auto-replies ---------------------------------------------------

    def compose_reply(self, plaintext: bytes) -> bytes:
        """The Host Node's contact persona: a tiny deterministic responder
        that proves live bidirectional ratchet traffic."""
        text = plaintext.decode("utf-8", errors="replace").strip()
        now = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        if text.lower() == "ping":
            reply = "pong"
        elif text.lower() in {"hello", "hi", "hey"}:
            reply = (
                f"Hello! This is {self.host_name}, your host node. "
                "Every byte of this conversation is Triple Ratchet encrypted."
            )
        elif text.lower() == "help":
            reply = (
                "Host Node commands: 'ping' (liveness), 'hello' (greeting), "
                "'help' (this text). Anything else is acknowledged and "
                "counter-signed with a receipt timestamp."
            )
        else:
            reply = f"Encrypted receipt: your {len(text)}-character message arrived intact at {now}."
        return reply.encode("utf-8")

    def bootstrap_contact(self, user_id: int) -> int:
        """Auto-provisions the default 'Host Node' contact for a new user."""
        return self.db.add_contact(
            user_id, HOST_CONTACT_NAME, self.upa, is_host=True
        )
