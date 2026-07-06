"""
End-to-end API tests: real passkey ceremonies (software authenticator),
real Triple Ratchet sessions on both sides of the wire.
"""
import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from omail.crypto.triple_ratchet import (
    PrekeyBundle,
    ResponderKeys,
    TripleRatchet,
    make_prekey_bundle,
)
from omail.db import Database
from omail.federation import FederationError
from omail.host import HostNode
from omail.server import create_app
from tests.soft_authenticator import SoftAuthenticator



def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _seed():
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


class PortalUser:
    """A test double for the browser client: passkey + client-side ratchet."""

    def __init__(self, client):
        self.client = client
        self.seed = _seed()
        self.identity_pub = ed25519.Ed25519PrivateKey.from_private_bytes(
            self.seed
        ).public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        origin = f"http://{client.host}:{client.port}"
        self.authenticator = SoftAuthenticator(client.host, origin)
        self.token = None
        self.info = None
        self.ratchets = {}       # contact upa -> TripleRatchet
        self.responder_keys = {} # prekey_id -> ResponderKeys

    @property
    def headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    async def register(self):
        resp = await self.client.post("/api/webauthn/register/begin", json={})
        begin = await resp.json()
        credential = self.authenticator.create(begin["options"])
        resp = await self.client.post(
            "/api/webauthn/register/complete",
            json={
                "ceremony": begin["ceremony"],
                "credential": credential,
                "identity_pub": _b64(self.identity_pub),
            },
        )
        assert resp.status == 200, await resp.text()
        self.info = await resp.json()
        self.token = self.info["token"]
        self.client.session.cookie_jar.clear()
        return self.info

    async def login(self):
        resp = await self.client.post("/api/webauthn/login/begin", json={})
        begin = await resp.json()
        assertion = self.authenticator.get(begin["options"])
        resp = await self.client.post(
            "/api/webauthn/login/complete",
            json={"ceremony": begin["ceremony"], "credential": assertion},
        )
        assert resp.status == 200, await resp.text()
        self.info = await resp.json()
        self.token = self.info["token"]
        self.client.session.cookie_jar.clear()
        return self.info

    async def send_to(self, contact, text: str):
        """Encrypts and sends; establishes a session if none exists."""
        upa = contact["upa"]
        prekey_id = None
        if upa not in self.ratchets:
            resp = await self.client.get(
                "/api/bundle", params={"upa": upa}, headers=self.headers
            )
            assert resp.status == 200, await resp.text()
            data = await resp.json()
            prekey_id = data["prekey_id"]
            self.ratchets[upa] = TripleRatchet.initiate(
                self.seed, PrekeyBundle.from_dict(data["bundle"])
            )
        envelope = self.ratchets[upa].encrypt(text.encode())
        payload = {
            "contact_id": contact["id"],
            "envelope": envelope,
            "archive": {"iv": "test", "ct": _b64(text.encode())},
        }
        if prekey_id is not None:
            payload["prekey_id"] = prekey_id
        resp = await self.client.post(
            "/api/messages/send", json=payload, headers=self.headers
        )
        assert resp.status == 200, await resp.text()
        return await resp.json()

    def open_envelope(self, upa: str, message: dict) -> bytes:
        """Decrypts an incoming envelope, handling handshake envelopes."""
        envelope = message["envelope"]
        if upa not in self.ratchets:
            assert "init" in envelope, "no session and no handshake"
            keys = self.responder_keys[envelope["prekey_id"]]
            self.ratchets[upa] = TripleRatchet.respond(keys, envelope["init"])
        return self.ratchets[upa].decrypt(envelope)


@pytest.fixture
def db():
    database = Database(":memory:")
    yield database
    database.close()


@pytest.fixture
def host(db):
    return HostNode(db, host_name="Test Harbor")


@pytest.fixture
def announcements():
    return []


@pytest.fixture
async def client(aiohttp_client, db, host, announcements):
    app = create_app(
        db, host, announce=announcements.append, start_tor_on_migration=False
    )
    return await aiohttp_client(app)


async def _new_user(client) -> PortalUser:
    user = PortalUser(client)
    await user.register()
    return user


async def test_index_renders_host_title(client):
    resp = await client.get("/")
    html = await resp.text()
    assert "<title>Test Harbor OMail</title>" in html


async def test_healthz(client, host):
    data = await (await client.get("/healthz")).json()
    assert data == {"status": "ok", "onion": host.onion}


async def test_registration_creates_upa_and_host_contact(client, host):
    user = await _new_user(client)
    assert user.info["upa"].startswith(host.onion + "/")
    assert user.info["host_name"] == "Test Harbor"

    contacts = await (
        await client.get("/api/contacts", headers=user.headers)
    ).json()
    assert len(contacts) == 1
    assert contacts[0]["name"] == "Administrator"
    assert contacts[0]["is_host"] is True
    assert contacts[0]["upa"] == host.upa


async def test_login_with_registered_passkey(client):
    user = await _new_user(client)
    first_upa = user.info["upa"]
    await user.login()
    assert user.info["upa"] == first_upa

    me = await (await client.get("/api/me", headers=user.headers)).json()
    assert me["handle"] == user.info["handle"]


async def test_api_requires_auth(client):
    for path in ("/api/me", "/api/contacts", "/api/vault"):
        resp = await client.get(path)
        assert resp.status == 401


async def test_vault_roundtrip_is_opaque(client, db):
    user = await _new_user(client)
    resp = await client.get("/api/vault", headers=user.headers)
    assert resp.status == 404

    blob = {"iv": "abc", "ct": "ZW5jcnlwdGVk", "kdf": "prf-hkdf-v1"}
    resp = await client.put("/api/vault", json=blob, headers=user.headers)
    assert resp.status == 200
    stored = await (await client.get("/api/vault", headers=user.headers)).json()
    assert stored == blob

    resp = await client.put("/api/vault", json={"nope": 1}, headers=user.headers)
    assert resp.status == 400


async def test_host_conversation_triple_ratchet(client, host):
    """Live bidirectional host<->client messaging, fully ratcheted."""
    user = await _new_user(client)
    contacts = await (
        await client.get("/api/contacts", headers=user.headers)
    ).json()
    host_contact = contacts[0]

    result = await user.send_to(host_contact, "ping")
    assert result["delivery"] == "host"

    messages = await (
        await client.get(
            "/api/messages",
            params={"contact_id": host_contact["id"]},
            headers=user.headers,
        )
    ).json()
    assert [m["direction"] for m in messages] == ["out", "in"]
    reply = messages[1]
    assert user.open_envelope(host_contact["upa"], reply) == b"pong"

    # Multiple rounds keep ratcheting
    await user.send_to(host_contact, "hello")
    messages = await (
        await client.get(
            "/api/messages",
            params={"contact_id": host_contact["id"]},
            headers=user.headers,
        )
    ).json()
    greeting = user.open_envelope(host_contact["upa"], messages[3])
    assert b"Test Harbor" in greeting


async def test_archive_destroys_transit_envelope(client):
    user = await _new_user(client)
    contacts = await (
        await client.get("/api/contacts", headers=user.headers)
    ).json()
    await user.send_to(contacts[0], "ping")
    messages = await (
        await client.get(
            "/api/messages",
            params={"contact_id": contacts[0]["id"]},
            headers=user.headers,
        )
    ).json()
    reply_id = messages[1]["id"]
    resp = await client.post(
        f"/api/messages/{reply_id}/archive",
        json={"iv": "x", "ct": "YXJjaGl2ZWQ"},
        headers=user.headers,
    )
    assert resp.status == 200
    messages = await (
        await client.get(
            "/api/messages",
            params={"contact_id": contacts[0]["id"]},
            headers=user.headers,
        )
    ).json()
    assert messages[1]["envelope"] is None
    assert messages[1]["archive"]["ct"] == "YXJjaGl2ZWQ"
    assert messages[1]["read"] is True


async def test_user_to_user_end_to_end(client, host):
    """Two tenants exchange mail through the blind host."""
    alice = await _new_user(client)
    bob = await _new_user(client)

    # Bob publishes client-generated prekey bundles (private halves stay
    # with Bob — here, in the test double's memory).
    bundle, keys = make_prekey_bundle(bob.seed)
    resp = await client.post(
        "/api/prekeys", json={"bundles": [bundle.to_dict()]}, headers=bob.headers
    )
    prekey_id = (await resp.json())["prekey_ids"][0]
    bob.responder_keys[prekey_id] = keys

    # Alice adds Bob by UPA and writes to him
    resp = await client.post(
        "/api/contacts",
        json={"name": "Bob", "upa": bob.info["upa"]},
        headers=alice.headers,
    )
    bob_contact = await resp.json()
    result = await alice.send_to(bob_contact, "hi bob, it's alice")
    assert result["delivery"] == "local"

    # Bob finds an auto-provisioned contact for Alice and decrypts
    bob_contacts = await (
        await client.get("/api/contacts", headers=bob.headers)
    ).json()
    from_alice = next(c for c in bob_contacts if c["upa"] == alice.info["upa"])
    messages = await (
        await client.get(
            "/api/messages",
            params={"contact_id": from_alice["id"]},
            headers=bob.headers,
        )
    ).json()
    assert len(messages) == 1
    plaintext = bob.open_envelope(alice.info["upa"], messages[0])
    assert plaintext == b"hi bob, it's alice"

    # And Bob replies over the now-established session
    reply = await bob.send_to(from_alice, "hey alice")
    assert reply["delivery"] == "local"
    alice_msgs = await (
        await client.get(
            "/api/messages",
            params={"contact_id": bob_contact["id"]},
            headers=alice.headers,
        )
    ).json()
    incoming = [m for m in alice_msgs if m["direction"] == "in"]
    assert alice.open_envelope(bob.info["upa"], incoming[0]) == b"hey alice"


async def test_bundle_endpoint_guards(client):
    user = await _new_user(client)
    resp = await client.get(
        "/api/bundle",
        params={"upa": "a" * 56 + ".onion/" + "b" * 56},
        headers=user.headers,
    )
    assert resp.status == 404

    # A user with no published prekeys can't be initiated against
    other = await _new_user(client)
    resp = await client.get(
        "/api/bundle", params={"upa": other.info["upa"]}, headers=user.headers
    )
    assert resp.status == 409


async def test_contact_validation(client):
    user = await _new_user(client)
    resp = await client.post(
        "/api/contacts",
        json={"name": "Eve", "upa": "eve@example.com"},
        headers=user.headers,
    )
    assert resp.status == 400


async def test_remote_upa_queues(client, host):
    user = await _new_user(client)
    # A syntactically valid UPA on a foreign host
    foreign_seed = _seed()
    foreign_pub = ed25519.Ed25519PrivateKey.from_private_bytes(
        foreign_seed
    ).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    from omail.upa import derive_upa, encode_pubkey
    foreign_upa = derive_upa(encode_pubkey(foreign_pub) + ".onion", foreign_pub)
    resp = await client.post(
        "/api/contacts",
        json={"name": "Far", "upa": foreign_upa},
        headers=user.headers,
    )
    contact = await resp.json()
    # Session bootstrap against a remote host isn't possible locally, so
    # fabricate an envelope: routing must still queue it blindly.
    resp = await client.post(
        "/api/messages/send",
        json={
            "contact_id": contact["id"],
            "envelope": {"header": {}, "ciphertext": "b64"},
        },
        headers=user.headers,
    )
    assert (await resp.json())["delivery"] == "queued-remote"


async def test_migration_promotes_to_sovereign(client, host, announcements):
    user = await _new_user(client)
    old_upa = user.info["upa"]
    resp = await client.post("/api/migrate", json={}, headers=user.headers)
    assert resp.status == 200
    result = await resp.json()
    assert result["old_upa"] == old_upa
    assert result["upa"] != old_upa
    assert result["onion"].endswith(".onion")
    assert result["onion"] != host.onion
    # The user part of the UPA (their key) is unchanged; routing moved
    assert result["upa"].split("/")[1] == old_upa.split("/")[1]
    assert result["tor_active"] is False

    me = await (await client.get("/api/me", headers=user.headers)).json()
    assert me["sovereign"] is True
    assert me["upa"] == result["upa"]
    assert me["mode"] == "host"

    # Terminal routing table confirmation happened
    assert any("HOST MODE" in line for line in announcements)
    assert any("routing table" in line for line in announcements)

    # Second promotion is rejected
    resp = await client.post("/api/migrate", json={}, headers=user.headers)
    assert resp.status == 400


async def test_websocket_push_on_host_reply(client):
    user = await _new_user(client)
    contacts = await (
        await client.get("/api/contacts", headers=user.headers)
    ).json()
    ws = await client.ws_connect("/api/ws", headers=user.headers)
    await user.send_to(contacts[0], "ping")
    event = await ws.receive_json(timeout=5)
    assert event["type"] == "message"
    assert event["contact_id"] == contacts[0]["id"]
    await ws.close()


# ---------------------------------------------------------------------------
# Device-key fallback (browsers where WebAuthn is unavailable)
# ---------------------------------------------------------------------------

def _device_pair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


async def _device_register(client, priv, pub, identity_pub):
    begin = await (
        await client.post("/api/devicekey/register/begin", json={})
    ).json()
    signature = priv.sign(begin["challenge"].encode())
    return await client.post(
        "/api/devicekey/register/complete",
        json={
            "ceremony": begin["ceremony"],
            "device_pub": _b64(pub),
            "signature": _b64(signature),
            "identity_pub": _b64(identity_pub),
        },
    )


async def test_device_key_register_login_and_vault(client, host):
    priv, pub = _device_pair()
    identity_seed = _seed()
    identity_pub = ed25519.Ed25519PrivateKey.from_private_bytes(
        identity_seed
    ).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    resp = await _device_register(client, priv, pub, identity_pub)
    assert resp.status == 200
    info = await resp.json()
    assert info["upa"].startswith(host.onion + "/")
    headers = {"Authorization": f"Bearer {info['token']}"}

    # Session works across the API surface, host contact bootstrapped
    me = await (await client.get("/api/me", headers=headers)).json()
    assert me["handle"] == info["handle"]
    contacts = await (await client.get("/api/contacts", headers=headers)).json()
    assert contacts[0]["name"] == "Administrator"

    # Vault round-trips (opaque to the server, same as passkey users)
    put = await client.put(
        "/api/vault", json={"ct": "b64ct", "iv": "b64iv"}, headers=headers
    )
    assert put.status == 200
    blob = await (await client.get("/api/vault", headers=headers)).json()
    assert blob["ct"] == "b64ct"

    # Fresh challenge-response login with the same device key
    begin = await (
        await client.post("/api/devicekey/login/begin", json={})
    ).json()
    signature = priv.sign(begin["challenge"].encode())
    login = await client.post(
        "/api/devicekey/login/complete",
        json={
            "ceremony": begin["ceremony"],
            "device_pub": _b64(pub),
            "signature": _b64(signature),
        },
    )
    assert login.status == 200
    relogged = await login.json()
    assert relogged["handle"] == info["handle"]


async def test_device_key_rejects_bad_signature_and_replay(client):
    priv, pub = _device_pair()
    identity_pub = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Wrong signature never creates a user
    begin = await (
        await client.post("/api/devicekey/register/begin", json={})
    ).json()
    resp = await client.post(
        "/api/devicekey/register/complete",
        json={
            "ceremony": begin["ceremony"],
            "device_pub": _b64(pub),
            "signature": _b64(b"\x00" * 64),
            "identity_pub": _b64(identity_pub),
        },
    )
    assert resp.status == 400

    # Real registration
    resp = await _device_register(client, priv, pub, identity_pub)
    assert resp.status == 200

    # Same device key cannot register twice
    other_identity = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    resp = await _device_register(client, priv, pub, other_identity)
    assert resp.status == 409

    # A login ceremony is single-use: replaying the consumed ceremony fails
    begin = await (
        await client.post("/api/devicekey/login/begin", json={})
    ).json()
    body = {
        "ceremony": begin["ceremony"],
        "device_pub": _b64(pub),
        "signature": _b64(priv.sign(begin["challenge"].encode())),
    }
    first = await client.post("/api/devicekey/login/complete", json=body)
    assert first.status == 200
    replay = await client.post("/api/devicekey/login/complete", json=body)
    assert replay.status == 400

    # Unknown device key is rejected even with a valid self-signature
    stranger_priv, stranger_pub = _device_pair()
    begin = await (
        await client.post("/api/devicekey/login/begin", json={})
    ).json()
    resp = await client.post(
        "/api/devicekey/login/complete",
        json={
            "ceremony": begin["ceremony"],
            "device_pub": _b64(stranger_pub),
            "signature": _b64(stranger_priv.sign(begin["challenge"].encode())),
        },
    )
    assert resp.status == 401


# ---------------------------------------------------------------------------
# Relationship slots (per-relationship inbound UPAs)
# ---------------------------------------------------------------------------

async def test_relationship_invite_mint_and_list(client, host):
    user = await _new_user(client)

    slot_seed = _seed()
    slot_pub = ed25519.Ed25519PrivateKey.from_private_bytes(
        slot_seed
    ).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    bundle, _keys = make_prekey_bundle(slot_seed)

    resp = await client.post(
        "/api/relationships",
        json={"label": "Bob", "slot_pub": _b64(slot_pub),
              "bundles": [bundle.to_dict()]},
        headers=user.headers,
    )
    assert resp.status == 200, await resp.text()
    rel = await resp.json()
    # The inbound UPA lives on THIS host and is the shareable invite
    assert rel["inbound_upa"].startswith(host.onion + "/")
    assert rel["label"] == "Bob"
    assert rel["state"] == "invited"
    assert rel["outbound_upa"] is None
    # It is a distinct per-relationship address, not the user's identity UPA
    assert rel["inbound_upa"] != user.info["upa"]

    listed = await (
        await client.get("/api/relationships", headers=user.headers)
    ).json()
    assert [r["inbound_upa"] for r in listed] == [rel["inbound_upa"]]


async def test_relationship_invite_requires_bundles(client):
    user = await _new_user(client)
    slot_pub = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    resp = await client.post(
        "/api/relationships",
        json={"label": "Bob", "slot_pub": _b64(slot_pub), "bundles": []},
        headers=user.headers,
    )
    assert resp.status == 400

    # Auth is required
    resp = await client.post("/api/relationships", json={})
    assert resp.status == 401


# ---------------------------------------------------------------------------
# Phase 2: per-relationship federation (same-host fast path)
# ---------------------------------------------------------------------------

def _slot_bundles(n=2):
    """Mints a relationship slot: a seed, its public key, n public prekey
    bundles, and the matching ResponderKeys (kept as the 'client' would keep
    them in its vault)."""
    seed = _seed()
    slot_pub = ed25519.Ed25519PrivateKey.from_private_bytes(
        seed
    ).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    bundles, keys = [], []
    for _ in range(n):
        b, k = make_prekey_bundle(seed)
        bundles.append(b.to_dict())
        keys.append(k)
    return seed, slot_pub, bundles, keys


async def test_relationship_federation_same_host(client, host):
    """Alice and Bob, two tenants on one node, connect via the invite
    handshake and exchange mail through per-relationship slots — the whole
    Phase 2 flow with federation short-circuited to the same host."""
    alice = await _new_user(client)
    bob = await _new_user(client)

    # Alice mints an invite slot for Bob and keeps its responder keys
    a_seed, a_pub, a_bundles, a_keys = _slot_bundles()
    resp = await client.post(
        "/api/relationships",
        json={"label": "Bob", "slot_pub": _b64(a_pub), "bundles": a_bundles},
        headers=alice.headers,
    )
    a_rel = await resp.json()
    invite_upa = a_rel["inbound_upa"]
    alice_slot_keys = dict(zip(a_rel["prekey_ids"], a_keys))

    # Bob accepts: mints his reverse slot and runs the connect handshake
    b_seed, b_pub, b_bundles, b_keys = _slot_bundles()
    resp = await client.post(
        "/api/relationships/accept",
        json={"invite_upa": invite_upa, "label": "Alice",
              "slot_pub": _b64(b_pub), "bundles": b_bundles},
        headers=bob.headers,
    )
    assert resp.status == 200, await resp.text()
    b_rel = await resp.json()
    assert b_rel["state"] == "connected"
    assert b_rel["outbound_upa"] == invite_upa
    bob_contact = b_rel["contact"]              # Bob's thread for Alice

    # Alice's side is now connected too, with a fresh thread for Bob
    a_rels = await (
        await client.get("/api/relationships", headers=alice.headers)
    ).json()
    assert a_rels[0]["state"] == "connected"
    assert a_rels[0]["outbound_upa"] == b_rel["inbound_upa"]
    alice_contacts = await (
        await client.get("/api/contacts", headers=alice.headers)
    ).json()
    alice_contact = next(c for c in alice_contacts if not c["is_host"])

    # Bob -> Alice: fetch Alice's slot bundle, initiate, deliver
    data = await (
        await client.get("/api/bundle", params={"upa": invite_upa},
                         headers=bob.headers)
    ).json()
    bt = TripleRatchet.initiate(b_seed, PrekeyBundle.from_dict(data["bundle"]))
    env = bt.encrypt(b"hi alice, it's bob")
    result = await client.post(
        "/api/messages/send",
        json={"contact_id": bob_contact["id"], "envelope": env,
              "prekey_id": data["prekey_id"],
              "archive": {"iv": "x", "ct": "x"}},
        headers=bob.headers,
    )
    assert (await result.json())["delivery"] == "local"

    # Alice reads and decrypts with her slot's responder key
    msgs = await (
        await client.get("/api/messages",
                         params={"contact_id": alice_contact["id"]},
                         headers=alice.headers)
    ).json()
    incoming = [m for m in msgs if m["direction"] == "in"]
    assert len(incoming) == 1
    env_in = incoming[0]["envelope"]
    at = TripleRatchet.respond(alice_slot_keys[env_in["prekey_id"]], env_in["init"])
    assert at.decrypt(env_in) == b"hi alice, it's bob"

    # Alice -> Bob over the established session
    reply = at.encrypt(b"hey bob, alice here")
    result = await client.post(
        "/api/messages/send",
        json={"contact_id": alice_contact["id"], "envelope": reply,
              "archive": {"iv": "x", "ct": "x"}},
        headers=alice.headers,
    )
    assert (await result.json())["delivery"] == "local"

    bmsgs = await (
        await client.get("/api/messages",
                         params={"contact_id": bob_contact["id"]},
                         headers=bob.headers)
    ).json()
    b_in = [m for m in bmsgs if m["direction"] == "in"]
    assert bt.decrypt(b_in[0]["envelope"]) == b"hey bob, alice here"


async def test_accept_unknown_invite_fails(client, host):
    bob = await _new_user(client)
    _seed_, pub, bundles, _keys = _slot_bundles()
    # A well-formed invite UPA on this host that was never minted
    bogus = host.user_upa(b"\x07" * 32)
    resp = await client.post(
        "/api/relationships/accept",
        json={"invite_upa": bogus, "label": "Ghost",
              "slot_pub": _b64(pub), "bundles": bundles},
        headers=bob.headers,
    )
    assert resp.status == 404


async def test_relationship_federation_two_hosts(aiohttp_client):
    """The same connect + message flow, but Alice and Bob live on two
    independent hosts. A transport injected into each FederationClient routes
    an onion to the other host's test client, proving the cross-host path
    deterministically without a live Tor."""
    db_a = Database(":memory:")
    host_a = HostNode(db_a, host_name="Alpha")
    db_b = Database(":memory:")
    host_b = HostNode(db_b, host_name="Beta")
    app_a = create_app(db_a, host_a, start_tor_on_migration=False)
    app_b = create_app(db_b, host_b, start_tor_on_migration=False)
    client_a = await aiohttp_client(app_a)
    client_b = await aiohttp_client(app_b)

    registry = {host_a.onion: client_a, host_b.onion: client_b}

    async def remote(peer_onion, path, payload):
        target = registry[peer_onion]
        if path.endswith("/bundle"):
            resp = await target.get(path, params=payload)
        else:
            resp = await target.post(path, json=payload)
        data = await resp.json()
        if resp.status >= 400:
            raise FederationError(resp.status, data.get("error", "fed error"))
        return data

    app_a["federation"].remote = remote
    app_b["federation"].remote = remote

    alice = PortalUser(client_a)
    await alice.register()
    bob = PortalUser(client_b)
    await bob.register()

    # Alice mints an invite on host A
    a_seed, a_pub, a_bundles, a_keys = _slot_bundles()
    a_rel = await (await client_a.post(
        "/api/relationships",
        json={"label": "Bob", "slot_pub": _b64(a_pub), "bundles": a_bundles},
        headers=alice.headers,
    )).json()
    invite_upa = a_rel["inbound_upa"]
    alice_slot_keys = dict(zip(a_rel["prekey_ids"], a_keys))
    assert invite_upa.startswith(host_a.onion + "/")

    # Bob accepts on host B -> the connect handshake crosses to host A
    b_seed, b_pub, b_bundles, b_keys = _slot_bundles()
    resp = await client_b.post(
        "/api/relationships/accept",
        json={"invite_upa": invite_upa, "label": "Alice",
              "slot_pub": _b64(b_pub), "bundles": b_bundles},
        headers=bob.headers,
    )
    assert resp.status == 200, await resp.text()
    b_rel = await resp.json()
    assert b_rel["state"] == "connected"
    assert b_rel["inbound_upa"].startswith(host_b.onion + "/")
    bob_contact = b_rel["contact"]

    # Alice's relationship on host A is now bound
    a_rels = await (
        await client_a.get("/api/relationships", headers=alice.headers)
    ).json()
    assert a_rels[0]["state"] == "connected"
    assert a_rels[0]["outbound_upa"] == b_rel["inbound_upa"]
    alice_contact = next(
        c for c in await (
            await client_a.get("/api/contacts", headers=alice.headers)
        ).json() if not c["is_host"]
    )

    # Bob -> Alice, across hosts
    data = await (await client_b.get(
        "/api/bundle", params={"upa": invite_upa}, headers=bob.headers
    )).json()
    bt = TripleRatchet.initiate(b_seed, PrekeyBundle.from_dict(data["bundle"]))
    env = bt.encrypt(b"cross-host hello")
    result = await client_b.post(
        "/api/messages/send",
        json={"contact_id": bob_contact["id"], "envelope": env,
              "prekey_id": data["prekey_id"], "archive": {"iv": "x", "ct": "x"}},
        headers=bob.headers,
    )
    assert (await result.json())["delivery"] == "federated"

    msgs = await (await client_a.get(
        "/api/messages", params={"contact_id": alice_contact["id"]},
        headers=alice.headers,
    )).json()
    env_in = [m for m in msgs if m["direction"] == "in"][0]["envelope"]
    at = TripleRatchet.respond(alice_slot_keys[env_in["prekey_id"]], env_in["init"])
    assert at.decrypt(env_in) == b"cross-host hello"

    # Alice -> Bob, across hosts
    reply = at.encrypt(b"cross-host reply")
    result = await client_a.post(
        "/api/messages/send",
        json={"contact_id": alice_contact["id"], "envelope": reply,
              "archive": {"iv": "x", "ct": "x"}},
        headers=alice.headers,
    )
    assert (await result.json())["delivery"] == "federated"

    bmsgs = await (await client_b.get(
        "/api/messages", params={"contact_id": bob_contact["id"]},
        headers=bob.headers,
    )).json()
    b_in = [m for m in bmsgs if m["direction"] == "in"][0]["envelope"]
    assert bt.decrypt(b_in) == b"cross-host reply"

    db_a.close()
    db_b.close()


# ---------------------------------------------------------------------------
# Phase 3: guest invites (see docs/concepts.md)
# ---------------------------------------------------------------------------

async def test_guest_invite_claim_via_passkey(client, host):
    """Alice mints a guest invite; Charlie claims it with a passkey and the
    result behaves like any tenant on Alice's host — same UPA before and
    after claim, Administrator contact bootstrapped, sessions work."""
    alice = await _new_user(client)

    resp = await client.post(
        "/api/guests", json={"label": "Charlie"}, headers=alice.headers
    )
    assert resp.status == 200, await resp.text()
    invite = await resp.json()
    assert invite["claimed"] is False
    assert invite["inbound_upa"].startswith(host.onion + "/")
    # A guest's inbound address is distinct from Alice's own identity UPA
    assert invite["inbound_upa"] != alice.info["upa"]

    listed = await (await client.get("/api/guests", headers=alice.headers)).json()
    assert listed[0]["inbound_upa"] == invite["inbound_upa"]
    assert listed[0]["claimed"] is False

    # Charlie claims it with a (software) passkey
    charlie_seed = _seed()
    charlie_pub = ed25519.Ed25519PrivateKey.from_private_bytes(
        charlie_seed
    ).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    origin = f"http://{client.host}:{client.port}"
    auth = SoftAuthenticator(client.host, origin)

    begin = await (await client.post(
        "/api/guests/claim/webauthn/begin",
        json={"inbound_upa": invite["inbound_upa"]},
    )).json()
    credential = auth.create(begin["options"])
    resp = await client.post(
        "/api/guests/claim/webauthn/complete",
        json={"ceremony": begin["ceremony"], "credential": credential,
              "identity_pub": _b64(charlie_pub)},
    )
    assert resp.status == 200, await resp.text()
    info = await resp.json()
    # The claimed account keeps the EXACT UPA Alice minted
    assert info["upa"] == invite["inbound_upa"]
    charlie_headers = {"Authorization": f"Bearer {info['token']}"}
    # The response set Charlie's session cookie on the shared test client;
    # clear it so later Authorization-header calls aren't shadowed by it
    # (mirrors what PortalUser.register/login do for the same reason).
    client.session.cookie_jar.clear()

    contacts = await (
        await client.get("/api/contacts", headers=charlie_headers)
    ).json()
    assert contacts[0]["name"] == "Administrator"

    listed = await (await client.get("/api/guests", headers=alice.headers)).json()
    assert listed[0]["claimed"] is True


async def test_guest_invite_single_use(client, host):
    alice = await _new_user(client)
    invite = await (await client.post(
        "/api/guests", json={"label": "Charlie"}, headers=alice.headers
    )).json()

    origin = f"http://{client.host}:{client.port}"
    auth1 = SoftAuthenticator(client.host, origin)
    begin = await (await client.post(
        "/api/guests/claim/webauthn/begin",
        json={"inbound_upa": invite["inbound_upa"]},
    )).json()
    credential = auth1.create(begin["options"])
    identity_pub = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    resp = await client.post(
        "/api/guests/claim/webauthn/complete",
        json={"ceremony": begin["ceremony"], "credential": credential,
              "identity_pub": _b64(identity_pub)},
    )
    assert resp.status == 200

    # A second claim attempt against the same invite is rejected
    resp = await client.post(
        "/api/guests/claim/webauthn/begin",
        json={"inbound_upa": invite["inbound_upa"]},
    )
    assert resp.status == 410

    # Unknown invite
    resp = await client.post(
        "/api/guests/claim/webauthn/begin",
        json={"inbound_upa": host.user_upa(b"\x09" * 32)},
    )
    assert resp.status == 404


async def test_guest_invite_claim_via_devicekey(client, host):
    alice = await _new_user(client)
    invite = await (await client.post(
        "/api/guests", json={"label": "Charlie"}, headers=alice.headers
    )).json()

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    identity_pub = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    begin = await (await client.post(
        "/api/guests/claim/devicekey/begin",
        json={"inbound_upa": invite["inbound_upa"]},
    )).json()
    signature = priv.sign(begin["challenge"].encode())
    resp = await client.post(
        "/api/guests/claim/devicekey/complete",
        json={"ceremony": begin["ceremony"], "device_pub": _b64(pub),
              "signature": _b64(signature), "identity_pub": _b64(identity_pub)},
    )
    assert resp.status == 200, await resp.text()
    info = await resp.json()
    assert info["upa"] == invite["inbound_upa"]

    # Login again with the same device key works normally (existing flow)
    login_begin = await (
        await client.post("/api/devicekey/login/begin", json={})
    ).json()
    resp = await client.post(
        "/api/devicekey/login/complete",
        json={"ceremony": login_begin["ceremony"], "device_pub": _b64(pub),
              "signature": _b64(priv.sign(login_begin["challenge"].encode()))},
    )
    assert resp.status == 200


# ---------------------------------------------------------------------------
# Phase 3: credentials list + multi-device linking
# ---------------------------------------------------------------------------

async def test_credentials_list(client):
    user = await _new_user(client)
    creds = await (
        await client.get("/api/credentials", headers=user.headers)
    ).json()
    assert len(creds) == 1
    assert creds[0]["kind"] == "passkey"


async def test_device_link_webauthn_to_webauthn(client):
    """Device A (passkey) links Device B (also passkey): the parcel round
    trips as opaque ciphertext and Device B ends up with its own credential
    on the SAME account."""
    alice = await _new_user(client)

    begin = await (
        await client.post("/api/devices/link/begin", json={}, headers=alice.headers)
    ).json()
    link_id = begin["link_id"]

    # Device A encrypts a parcel with a link_secret only it and Device B
    # know (simulated here as a fixed 32-byte value); the server never sees
    # it in plaintext or the key.
    parcel = {"iv": "sim-iv", "ct": "sim-ciphertext-of-vault"}
    resp = await client.post(
        "/api/devices/link/deliver",
        json={"link_id": link_id, "parcel": parcel},
        headers=alice.headers,
    )
    assert resp.status == 200

    # Device B fetches it (no auth) and gets the opaque blob back verbatim
    fetched = await (
        await client.get("/api/devices/link/fetch", params={"link_id": link_id})
    ).json()
    assert fetched == {"ready": True, "parcel": parcel}

    # Device B completes its own passkey ceremony against the link
    origin = f"http://{client.host}:{client.port}"
    auth_b = SoftAuthenticator(client.host, origin)
    claim_begin = await (await client.post(
        "/api/devices/link/claim/webauthn/begin", json={"link_id": link_id}
    )).json()
    credential = auth_b.create(claim_begin["options"])
    resp = await client.post(
        "/api/devices/link/claim/webauthn/complete",
        json={"ceremony": claim_begin["ceremony"], "credential": credential},
    )
    assert resp.status == 200, await resp.text()
    info = await resp.json()
    assert info["upa"] == alice.info["upa"]  # same account, new device

    creds = await (
        await client.get("/api/credentials", headers=alice.headers)
    ).json()
    assert len(creds) == 2  # original passkey + the linked device's

    # The link is single-use
    resp = await client.get(
        "/api/devices/link/fetch", params={"link_id": link_id}
    )
    assert resp.status == 410


async def test_device_link_devicekey_variant_and_guards(client):
    alice = await _new_user(client)
    begin = await (
        await client.post("/api/devices/link/begin", json={}, headers=alice.headers)
    ).json()
    link_id = begin["link_id"]

    # Fetch before any parcel delivered
    pending = await (
        await client.get("/api/devices/link/fetch", params={"link_id": link_id})
    ).json()
    assert pending == {"ready": False}

    # A different user cannot deliver to someone else's link
    bob = await _new_user(client)
    resp = await client.post(
        "/api/devices/link/deliver",
        json={"link_id": link_id, "parcel": {"iv": "x", "ct": "y"}},
        headers=bob.headers,
    )
    assert resp.status == 404

    await client.post(
        "/api/devices/link/deliver",
        json={"link_id": link_id, "parcel": {"iv": "x", "ct": "y"}},
        headers=alice.headers,
    )

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    claim_begin = await (await client.post(
        "/api/devices/link/claim/devicekey/begin", json={"link_id": link_id}
    )).json()
    signature = priv.sign(claim_begin["challenge"].encode())
    resp = await client.post(
        "/api/devices/link/claim/devicekey/complete",
        json={"ceremony": claim_begin["ceremony"], "device_pub": _b64(pub),
              "signature": _b64(signature)},
    )
    assert resp.status == 200, await resp.text()
    info = await resp.json()
    assert info["upa"] == alice.info["upa"]

    # Unknown link_id
    resp = await client.post(
        "/api/devices/link/claim/devicekey/begin", json={"link_id": "nope"}
    )
    assert resp.status == 404
