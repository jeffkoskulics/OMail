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
from omail.host import HostNode
from omail.server import create_app
from tests.soft_authenticator import SoftAuthenticator

pytest_plugins = "aiohttp.pytest_plugin"


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
    assert contacts[0]["name"] == "Host Node"
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
