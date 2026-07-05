"""
Triple Ratchet protocol.

The Triple Ratchet extends Signal's Double Ratchet with a third,
post-quantum KEM ratchet:

  1. DH ratchet     — each epoch turns a fresh X25519 Diffie-Hellman
                      output into new root/chain keys (forward secrecy +
                      post-compromise security against classical attackers).
  2. Symmetric-key ratchet — per-message HMAC chains derive one-time
                      AES-256-GCM message keys (forward secrecy per message).
  3. KEM ratchet    — every DH epoch additionally encapsulates a fresh
                      shared secret to the peer's newest KEM public key
                      (ML-KEM-768 by default) and mixes it into the root
                      KDF, extending post-compromise security to quantum
                      adversaries.

Session establishment is a PQXDH-style hybrid handshake: three X25519
DHs (identity/ephemeral cross-exchanges against a signed prekey) plus one
KEM encapsulation, all fed through HKDF to seed the root key.

Wire format (all binary fields base64, JSON envelopes):

  handshake blob (attached to the session's first message):
    {"ik": <initiator Ed25519 identity pub>,
     "ik_x": <initiator X25519 identity pub>,
     "ek": <initiator ephemeral X25519 pub>,
     "kem_ct0": <KEM ciphertext to responder's prekey-bundle KEM key>,
     "kem_alg": "ML-KEM-768" | "X25519"}

  message header (authenticated as GCM associated data):
    {"dh": <sender's current ratchet X25519 pub>,
     "kem_pub": <sender's newest KEM encapsulation key>,
     "kem_ct": <KEM ciphertext to receiver's newest KEM key>,
     "n": <message number in chain>, "pn": <length of previous chain>}

The associated data is the canonical JSON of the header (sorted keys, no
whitespace), so a tampered header fails AEAD verification.
"""
from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import json
import os
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from omail.crypto.convert import (
    ed25519_priv_to_x25519,
    ed25519_pub_to_x25519,
    x25519_priv_bytes,
    x25519_pub_bytes,
)
from omail.crypto.kem import ML_KEM_768_NAME, get_kem

MAX_SKIP = 512

_ROOT_INFO = b"omail-ratchet-root"
_X3DH_INFO = b"omail-x3dh"
_MSG_INFO = b"omail-msg"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data)


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac_mod.new(key, data, hashlib.sha256).digest()


def _kdf_root(root_key: bytes, dh_out: bytes, kem_ss: bytes) -> Tuple[bytes, bytes]:
    """Mixes a DH output and a KEM shared secret into the root key.
    Returns (new_root_key, new_chain_key)."""
    okm = _hkdf(dh_out + kem_ss, salt=root_key, info=_ROOT_INFO, length=64)
    return okm[:32], okm[32:]

def _kdf_chain(chain_key: bytes) -> Tuple[bytes, bytes]:
    """Advances a symmetric chain. Returns (next_chain_key, message_key)."""
    return _hmac(chain_key, b"\x02"), _hmac(chain_key, b"\x01")


def _canonical_header(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()


def _encrypt(message_key: bytes, plaintext: bytes, ad: bytes) -> bytes:
    okm = _hkdf(message_key, salt=b"", info=_MSG_INFO, length=44)
    return AESGCM(okm[:32]).encrypt(okm[32:44], plaintext, ad)


def _decrypt(message_key: bytes, ciphertext: bytes, ad: bytes) -> bytes:
    okm = _hkdf(message_key, salt=b"", info=_MSG_INFO, length=44)
    return AESGCM(okm[:32]).decrypt(okm[32:44], ciphertext, ad)


def _dh(priv_bytes: bytes, pub_bytes: bytes) -> bytes:
    priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    pub = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
    return priv.exchange(pub)


def _gen_x25519() -> Tuple[bytes, bytes]:
    """Returns (priv_bytes, pub_bytes)."""
    priv = x25519.X25519PrivateKey.generate()
    return x25519_priv_bytes(priv), x25519_pub_bytes(priv.public_key())


@dataclass
class PrekeyBundle:
    """A responder's published handshake material."""

    ik_ed: bytes        # Ed25519 identity public key
    ik_x: bytes         # X25519 identity public key (birational map of ik_ed)
    spk: bytes          # signed prekey (X25519 public)
    spk_sig: bytes      # Ed25519 signature over spk by ik_ed
    kem_pub: bytes      # initial KEM encapsulation key
    kem_alg: str = ML_KEM_768_NAME

    def to_dict(self) -> dict:
        return {
            "ik_ed": _b64(self.ik_ed),
            "ik_x": _b64(self.ik_x),
            "spk": _b64(self.spk),
            "spk_sig": _b64(self.spk_sig),
            "kem_pub": _b64(self.kem_pub),
            "kem_alg": self.kem_alg,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PrekeyBundle":
        return cls(
            ik_ed=_unb64(data["ik_ed"]),
            ik_x=_unb64(data["ik_x"]),
            spk=_unb64(data["spk"]),
            spk_sig=_unb64(data["spk_sig"]),
            kem_pub=_unb64(data["kem_pub"]),
            kem_alg=data["kem_alg"],
        )

    def verify(self) -> None:
        """Checks the prekey signature against the identity key."""
        ed25519.Ed25519PublicKey.from_public_bytes(self.ik_ed).verify(
            self.spk_sig, self.spk
        )


@dataclass
class ResponderKeys:
    """The responder's private handshake material matching a PrekeyBundle."""

    ik_ed_priv: bytes   # Ed25519 identity seed
    spk_priv: bytes     # signed prekey private
    kem_priv: bytes     # KEM decapsulation key
    kem_alg: str = ML_KEM_768_NAME


def make_prekey_bundle(
    ik_ed_priv: bytes, kem_alg: str = ML_KEM_768_NAME
) -> Tuple[PrekeyBundle, ResponderKeys]:
    """Generates a fresh signed prekey + KEM key pair for a responder whose
    Ed25519 identity seed is `ik_ed_priv`."""
    ik = ed25519.Ed25519PrivateKey.from_private_bytes(ik_ed_priv)
    ik_ed = ik.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    ik_x = x25519_pub_bytes(ed25519_pub_to_x25519(ik.public_key()))
    spk_priv, spk_pub = _gen_x25519()
    kem = get_kem(kem_alg)
    kem_pub, kem_priv = kem.generate_keypair()
    bundle = PrekeyBundle(
        ik_ed=ik_ed,
        ik_x=ik_x,
        spk=spk_pub,
        spk_sig=ik.sign(spk_pub),
        kem_pub=kem_pub,
        kem_alg=kem_alg,
    )
    return bundle, ResponderKeys(
        ik_ed_priv=ik_ed_priv, spk_priv=spk_priv, kem_priv=kem_priv, kem_alg=kem_alg
    )


class TripleRatchet:
    """A single peer's Triple Ratchet session state.

    Create sessions with `initiate()` (the party that fetched a prekey
    bundle) or `respond()` (the party whose bundle was used). The state is
    JSON-serializable via `to_dict()` / `from_dict()` so it can live in an
    encrypted vault (client) or the host database (host).
    """

    def __init__(self) -> None:
        self.kem_alg: str = ML_KEM_768_NAME
        self.root_key: bytes = b""
        self.dh_priv: bytes = b""
        self.dh_pub: bytes = b""
        self.remote_dh_pub: Optional[bytes] = None
        self.kem_priv: bytes = b""          # our newest decapsulation key
        self.kem_pub: bytes = b""           # its public half (goes in headers)
        self.prev_kem_priv: bytes = b""     # previous epoch fallback
        self.remote_kem_pub: Optional[bytes] = None
        self.send_kem_ct: bytes = b""       # ciphertext for current send epoch
        self.ck_send: Optional[bytes] = None
        self.ck_recv: Optional[bytes] = None
        self.n_send: int = 0
        self.n_recv: int = 0
        self.pn: int = 0
        self.skipped: Dict[Tuple[str, int], bytes] = {}
        self.handshake: Optional[dict] = None  # attached to first sent message

    # ------------------------------------------------------------------
    # Session establishment (PQXDH-style hybrid X3DH)
    # ------------------------------------------------------------------

    @classmethod
    def initiate(cls, ik_ed_priv: bytes, bundle: PrekeyBundle) -> "TripleRatchet":
        """Starts a session against a peer's prekey bundle. The returned
        ratchet is ready to encrypt; its first envelope carries the
        handshake blob."""
        bundle.verify()
        kem = get_kem(bundle.kem_alg)

        ik = ed25519.Ed25519PrivateKey.from_private_bytes(ik_ed_priv)
        ik_x_priv = x25519_priv_bytes(ed25519_priv_to_x25519(ik))
        ik_ed_pub = ik.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        ik_x_pub = x25519_pub_bytes(ed25519_pub_to_x25519(ik.public_key()))
        ek_priv, ek_pub = _gen_x25519()

        dh1 = _dh(ik_x_priv, bundle.spk)
        dh2 = _dh(ek_priv, bundle.ik_x)
        dh3 = _dh(ek_priv, bundle.spk)
        kem_ct0, kem_ss0 = kem.encaps(bundle.kem_pub)
        sk = _hkdf(dh1 + dh2 + dh3 + kem_ss0, salt=b"\x00" * 32, info=_X3DH_INFO, length=32)

        state = cls()
        state.kem_alg = bundle.kem_alg
        state.root_key = sk
        state.remote_dh_pub = bundle.spk
        state.remote_kem_pub = bundle.kem_pub
        state.handshake = {
            "ik": _b64(ik_ed_pub),
            "ik_x": _b64(ik_x_pub),
            "ek": _b64(ek_pub),
            "kem_ct0": _b64(kem_ct0),
            "kem_alg": bundle.kem_alg,
        }
        # ck_send is None, so the first encrypt() performs the initial
        # DH+KEM send ratchet step against the bundle's signed prekey.
        return state

    @classmethod
    def respond(
        cls, keys: ResponderKeys, handshake: dict
    ) -> "TripleRatchet":
        """Accepts a session initiated against our prekey bundle. The
        handshake blob comes from the first received envelope."""
        if handshake["kem_alg"] != keys.kem_alg:
            raise ValueError("Handshake KEM algorithm mismatch")
        kem = get_kem(keys.kem_alg)

        ik = ed25519.Ed25519PrivateKey.from_private_bytes(keys.ik_ed_priv)
        ik_x_priv = x25519_priv_bytes(ed25519_priv_to_x25519(ik))
        spk_priv = keys.spk_priv

        initiator_ik_x = _unb64(handshake["ik_x"])
        initiator_ek = _unb64(handshake["ek"])

        dh1 = _dh(spk_priv, initiator_ik_x)
        dh2 = _dh(ik_x_priv, initiator_ek)
        dh3 = _dh(spk_priv, initiator_ek)
        kem_ss0 = kem.decaps(keys.kem_priv, _unb64(handshake["kem_ct0"]))
        sk = _hkdf(dh1 + dh2 + dh3 + kem_ss0, salt=b"\x00" * 32, info=_X3DH_INFO, length=32)

        state = cls()
        state.kem_alg = keys.kem_alg
        state.root_key = sk
        # Our ratchet DH key starts as the signed prekey; the initiator's
        # first send step ratcheted against it.
        state.dh_priv = spk_priv
        priv = x25519.X25519PrivateKey.from_private_bytes(spk_priv)
        state.dh_pub = x25519_pub_bytes(priv.public_key())
        state.kem_priv = keys.kem_priv
        state.kem_pub = b""  # replaced on our first send step
        return state

    # ------------------------------------------------------------------
    # Ratchet steps
    # ------------------------------------------------------------------

    def _ratchet_send_step(self) -> None:
        """DH + KEM ratchet step performed when we start a new send epoch."""
        kem = get_kem(self.kem_alg)
        self.dh_priv, self.dh_pub = _gen_x25519()
        dh_out = _dh(self.dh_priv, self.remote_dh_pub)
        self.send_kem_ct, kem_ss = kem.encaps(self.remote_kem_pub)
        # Rotate our own KEM key pair; the new public half travels in headers.
        new_kem_pub, new_kem_priv = kem.generate_keypair()
        self.prev_kem_priv = self.kem_priv
        self.kem_priv, self.kem_pub = new_kem_priv, new_kem_pub
        self.root_key, self.ck_send = _kdf_root(self.root_key, dh_out, kem_ss)
        self.pn = self.n_send
        self.n_send = 0

    def _ratchet_recv_step(self, header: dict) -> None:
        """DH + KEM ratchet step triggered by a new remote ratchet key."""
        kem = get_kem(self.kem_alg)
        self.remote_dh_pub = _unb64(header["dh"])
        self.remote_kem_pub = _unb64(header["kem_pub"])
        dh_out = _dh(self.dh_priv, self.remote_dh_pub)
        kem_ct = _unb64(header["kem_ct"])
        try:
            kem_ss = kem.decaps(self.kem_priv, kem_ct)
        except Exception:
            if not self.prev_kem_priv:
                raise
            kem_ss = kem.decaps(self.prev_kem_priv, kem_ct)
        self.root_key, self.ck_recv = _kdf_root(self.root_key, dh_out, kem_ss)
        self.n_recv = 0
        # Our sending chain is now stale; the next encrypt() starts a new
        # send epoch ratcheted against the peer's fresh keys.
        self.ck_send = None

    # ------------------------------------------------------------------
    # Encrypt / decrypt
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> dict:
        """Encrypts a payload; returns the JSON-safe envelope."""
        if self.ck_send is None:
            self._ratchet_send_step()
        ck, mk = _kdf_chain(self.ck_send)
        self.ck_send = ck
        header = {
            "dh": _b64(self.dh_pub),
            "kem_pub": _b64(self.kem_pub),
            "kem_ct": _b64(self.send_kem_ct),
            "n": self.n_send,
            "pn": self.pn,
        }
        self.n_send += 1
        envelope = {
            "v": 1,
            "header": header,
            "ciphertext": _b64(_encrypt(mk, plaintext, _canonical_header(header))),
        }
        if self.handshake is not None:
            envelope["init"] = self.handshake
            self.handshake = None
        return envelope

    def decrypt(self, envelope: dict) -> bytes:
        """Decrypts an envelope, advancing ratchets as needed. Handles
        out-of-order delivery via skipped message keys."""
        header = envelope["header"]
        ad = _canonical_header(header)
        ciphertext = _unb64(envelope["ciphertext"])

        skipped_key = (header["dh"], header["n"])
        if skipped_key in self.skipped:
            mk = self.skipped.pop(skipped_key)
            return _decrypt(mk, ciphertext, ad)

        remote_dh = _unb64(header["dh"])
        if remote_dh != self.remote_dh_pub:
            # New epoch: bank keys left in the outgoing chain's counterpart,
            # then take a receiving ratchet step.
            self._skip_message_keys(header["pn"])
            self._ratchet_recv_step(header)
        self._skip_message_keys(header["n"])

        ck, mk = _kdf_chain(self.ck_recv)
        self.ck_recv = ck
        self.n_recv += 1
        return _decrypt(mk, ciphertext, ad)

    def _skip_message_keys(self, until: int) -> None:
        if self.ck_recv is None:
            if until > 0:
                raise ValueError("No receiving chain to skip into")
            return
        if self.n_recv + MAX_SKIP < until:
            raise ValueError("Too many skipped messages")
        dh_key = _b64(self.remote_dh_pub)
        while self.n_recv < until:
            self.ck_recv, mk = _kdf_chain(self.ck_recv)
            self.skipped[(dh_key, self.n_recv)] = mk
            self.n_recv += 1
            if len(self.skipped) > MAX_SKIP:
                self.skipped.pop(next(iter(self.skipped)))

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        opt = lambda v: _b64(v) if v else None
        return {
            "kem_alg": self.kem_alg,
            "root_key": _b64(self.root_key),
            "dh_priv": opt(self.dh_priv),
            "dh_pub": opt(self.dh_pub),
            "remote_dh_pub": opt(self.remote_dh_pub),
            "kem_priv": opt(self.kem_priv),
            "kem_pub": opt(self.kem_pub),
            "prev_kem_priv": opt(self.prev_kem_priv),
            "remote_kem_pub": opt(self.remote_kem_pub),
            "send_kem_ct": opt(self.send_kem_ct),
            "ck_send": opt(self.ck_send),
            "ck_recv": opt(self.ck_recv),
            "n_send": self.n_send,
            "n_recv": self.n_recv,
            "pn": self.pn,
            "skipped": [
                {"dh": dh, "n": n, "mk": _b64(mk)}
                for (dh, n), mk in self.skipped.items()
            ],
            "handshake": self.handshake,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TripleRatchet":
        unopt = lambda v: _unb64(v) if v else b""
        state = cls()
        state.kem_alg = data["kem_alg"]
        state.root_key = _unb64(data["root_key"])
        state.dh_priv = unopt(data["dh_priv"])
        state.dh_pub = unopt(data["dh_pub"])
        state.remote_dh_pub = _unb64(data["remote_dh_pub"]) if data["remote_dh_pub"] else None
        state.kem_priv = unopt(data["kem_priv"])
        state.kem_pub = unopt(data["kem_pub"])
        state.prev_kem_priv = unopt(data["prev_kem_priv"])
        state.remote_kem_pub = _unb64(data["remote_kem_pub"]) if data["remote_kem_pub"] else None
        state.send_kem_ct = unopt(data["send_kem_ct"])
        state.ck_send = _unb64(data["ck_send"]) if data["ck_send"] else None
        state.ck_recv = _unb64(data["ck_recv"]) if data["ck_recv"] else None
        state.n_send = data["n_send"]
        state.n_recv = data["n_recv"]
        state.pn = data["pn"]
        state.skipped = {
            (item["dh"], item["n"]): _unb64(item["mk"]) for item in data["skipped"]
        }
        state.handshake = data.get("handshake")
        return state
