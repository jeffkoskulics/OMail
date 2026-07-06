"""
The OMail web portal and messaging API (aiohttp).

Served on 127.0.0.1 and reached exclusively through the node's Tor onion
service in production; localhost access exists for development. Passkey
RP identity follows the request Host header, so credentials minted over
the .onion address stay bound to it.

Zero-knowledge boundary: every API below either moves opaque ciphertext
(vault blobs, ratchet envelopes, archives) or public material (UPAs,
prekey bundles). The only plaintext the node ever sees is its own side of
Host Node conversations — the host is the peer in those by design.
"""
import base64
import json
import os
import secrets
import time
from importlib import resources
from typing import Dict, Optional, Set

from aiohttp import WSMsgType, web
from cryptography.hazmat.primitives.asymmetric import ed25519

from omail.db import Database
from omail.host import HostNode
from omail.migration import promote_to_sovereign
from omail.upa import parse_upa
from omail.webauthn import PasskeyManager, new_handle

SESSION_COOKIE = "omail_session"
CEREMONY_TTL = 300.0

# Device-key credentials share the credentials table with passkeys; the
# prefix keeps their IDs disjoint from WebAuthn credential IDs.
DEVICE_CRED_PREFIX = b"device-key:"


def _json_error(status: int, message: str) -> web.Response:
    return web.json_response({"error": message}, status=status)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(
    db: Database,
    host: HostNode,
    announce=print,
    tor_options: Optional[dict] = None,
    start_tor_on_migration: bool = True,
) -> web.Application:
    app = web.Application()
    app["db"] = db
    app["host"] = host
    app["announce"] = announce
    app["tor_options"] = tor_options or {}
    app["start_tor_on_migration"] = start_tor_on_migration
    app["passkey_managers"] = {}
    app["ceremonies"] = {}
    app["ws_connections"] = {}

    # One-time migration for nodes created before the rename: existing
    # tenants keep a host contact stored under the old default label.
    from omail.host import HOST_CONTACT_NAME
    renamed = db.rename_host_contacts(HOST_CONTACT_NAME, old_name="Host Node")
    if renamed:
        announce(f"[users] renamed {renamed} host contact(s) to {HOST_CONTACT_NAME}")

    app.router.add_get("/", index)
    app.router.add_get("/healthz", healthz)
    app.router.add_post("/api/webauthn/register/begin", register_begin)
    app.router.add_post("/api/webauthn/register/complete", register_complete)
    app.router.add_post("/api/webauthn/login/begin", login_begin)
    app.router.add_post("/api/webauthn/login/complete", login_complete)
    app.router.add_post("/api/devicekey/register/begin", device_register_begin)
    app.router.add_post("/api/devicekey/register/complete", device_register_complete)
    app.router.add_post("/api/devicekey/login/begin", device_login_begin)
    app.router.add_post("/api/devicekey/login/complete", device_login_complete)
    app.router.add_post("/api/logout", logout)
    app.router.add_get("/api/me", me)
    app.router.add_get("/api/vault", vault_get)
    app.router.add_put("/api/vault", vault_put)
    app.router.add_get("/api/contacts", contacts_list)
    app.router.add_post("/api/contacts", contacts_add)
    app.router.add_get("/api/bundle", bundle_get)
    app.router.add_post("/api/prekeys", prekeys_publish)
    app.router.add_get("/api/messages", messages_list)
    app.router.add_post("/api/messages/send", messages_send)
    app.router.add_post("/api/messages/{message_id}/archive", message_archive)
    app.router.add_post("/api/migrate", migrate)
    app.router.add_get("/api/ws", websocket_handler)

    static_dir = resources.files("omail") / "static"
    app.router.add_static("/static/", path=str(static_dir), name="static")
    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _passkeys(request: web.Request) -> PasskeyManager:
    """One PasskeyManager per request Host (rp_id must match the origin)."""
    host_header = request.headers.get("Host", "localhost:8000")
    rp_id = host_header.split(":")[0]
    managers = request.app["passkey_managers"]
    if rp_id not in managers:
        host: HostNode = request.app["host"]
        managers[rp_id] = PasskeyManager(
            rp_id,
            f"{host.host_name} OMail",
            extra_origins={f"http://{host_header}", f"https://{host_header}"},
        )
    return managers[rp_id]


def _store_ceremony(request: web.Request, kind: str, state: dict, **extra) -> str:
    ceremonies = request.app["ceremonies"]
    now = time.time()
    for token in [t for t, c in ceremonies.items() if c["expires"] < now]:
        del ceremonies[token]
    token = secrets.token_urlsafe(24)
    ceremonies[token] = {
        "kind": kind,
        "state": state,
        "expires": now + CEREMONY_TTL,
        **extra,
    }
    return token


def _take_ceremony(request: web.Request, token: str, kind: str) -> Optional[dict]:
    ceremony = request.app["ceremonies"].pop(token, None)
    if not ceremony or ceremony["kind"] != kind or ceremony["expires"] < time.time():
        return None
    return ceremony


def _session_user(request: web.Request):
    db: Database = request.app["db"]
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[len("Bearer "):]
    if not token:
        return None
    session = db.get_auth_session(token)
    return db.get_user(session["user_id"]) if session else None


def _require_user(request: web.Request):
    user = _session_user(request)
    if user is None:
        raise web.HTTPUnauthorized(
            text=json.dumps({"error": "Passkey authentication required"}),
            content_type="application/json",
        )
    return user


def _set_session(response: web.Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="Strict", path="/"
    )


async def _notify(app: web.Application, user_id: int, payload: dict) -> None:
    for ws in set(app["ws_connections"].get(user_id, ())):
        try:
            await ws.send_json(payload)
        except Exception:
            app["ws_connections"][user_id].discard(ws)


def _user_json(user, host: HostNode, db: Database) -> dict:
    return {
        "handle": user["handle"],
        "upa": user["upa"],
        "sovereign": bool(user["sovereign"]),
        "host_name": host.host_name,
        "host_onion": host.onion,
        "host_upa": host.upa,
        "mode": db.get_config("mode", "tenant"),
    }


# ---------------------------------------------------------------------------
# Portal
# ---------------------------------------------------------------------------

async def index(request: web.Request) -> web.Response:
    host: HostNode = request.app["host"]
    html = (resources.files("omail") / "static" / "index.html").read_text()
    html = html.replace("{{HOST_NAME}}", host.host_name)
    html = html.replace("{{HOST_ONION}}", host.onion)
    return web.Response(text=html, content_type="text/html")


async def healthz(request: web.Request) -> web.Response:
    host: HostNode = request.app["host"]
    return web.json_response({"status": "ok", "onion": host.onion})


# ---------------------------------------------------------------------------
# Passkey ceremonies
# ---------------------------------------------------------------------------

async def register_begin(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    handle = new_handle()
    while db.get_user_by_handle(handle):
        handle = new_handle()
    user_id_bytes = os.urandom(16)
    options, state = _passkeys(request).begin_registration(handle, user_id_bytes)
    token = _store_ceremony(
        request, "register", state,
        handle=handle,
        user_id_b64=base64.b64encode(user_id_bytes).decode(),
    )
    return web.json_response(
        {"ceremony": token, "handle": handle,
         "options": json.loads(json.dumps(options, default=str))}
    )


async def register_complete(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    host: HostNode = request.app["host"]
    body = await request.json()
    ceremony = _take_ceremony(request, body.get("ceremony", ""), "register")
    if ceremony is None:
        return _json_error(400, "Unknown or expired ceremony")
    try:
        identity_pub = base64.b64decode(body["identity_pub"])
        cred_id, cred_blob, sign_count = _passkeys(request).complete_registration(
            ceremony["state"], body["credential"]
        )
        upa = host.user_upa(identity_pub)
    except Exception as exc:
        return _json_error(400, f"Registration failed: {exc}")

    user_id = db.create_user(ceremony["handle"], upa, identity_pub)
    db.add_credential(user_id, cred_id, cred_blob, sign_count)
    host.bootstrap_contact(user_id)
    token = db.create_auth_session(user_id)
    request.app["announce"](
        f"[users] new tenant {ceremony['handle']} onboarded (passkey, zero data)"
    )
    response = web.json_response(
        {"token": token, **_user_json(db.get_user(user_id), host, db)}
    )
    _set_session(response, token)
    return response


async def login_begin(request: web.Request) -> web.Response:
    options, state = _passkeys(request).begin_authentication()
    token = _store_ceremony(request, "login", state)
    return web.json_response(
        {"ceremony": token,
         "options": json.loads(json.dumps(options, default=str))}
    )


async def login_complete(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    host: HostNode = request.app["host"]
    body = await request.json()
    ceremony = _take_ceremony(request, body.get("ceremony", ""), "login")
    if ceremony is None:
        return _json_error(400, "Unknown or expired ceremony")
    credential = body.get("credential", {})
    try:
        raw_id = base64.urlsafe_b64decode(
            credential["rawId"] + "=" * (-len(credential["rawId"]) % 4)
        )
        stored = db.get_credential(raw_id)
        if stored is None:
            return _json_error(401, "Unknown passkey")
        _passkeys(request).complete_authentication(
            ceremony["state"], credential, [bytes(stored["public_key"])]
        )
    except web.HTTPException:
        raise
    except Exception as exc:
        return _json_error(401, f"Authentication failed: {exc}")

    db.update_sign_count(raw_id, stored["sign_count"] + 1)
    user = db.get_user(stored["user_id"])
    token = db.create_auth_session(user["id"])
    response = web.json_response({"token": token, **_user_json(user, host, db)})
    _set_session(response, token)
    return response


# ---------------------------------------------------------------------------
# Device-key fallback (browsers where WebAuthn is unavailable or blocked —
# e.g. Tor Browser, or plain-http .onion origins in Chromium). The browser
# generates an Ed25519 key, keeps it locally, and authenticates by signing
# a server challenge. Strictly weaker than a passkey: the key is only as
# safe as the browser profile, and the UI says so loudly.
# ---------------------------------------------------------------------------

def _verify_device_signature(device_pub: bytes, signature: bytes,
                             challenge: str) -> None:
    if len(device_pub) != 32:
        raise ValueError("Device key must be a raw 32-byte Ed25519 public key")
    ed25519.Ed25519PublicKey.from_public_bytes(device_pub).verify(
        signature, challenge.encode()
    )


async def device_register_begin(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    handle = new_handle()
    while db.get_user_by_handle(handle):
        handle = new_handle()
    challenge = secrets.token_urlsafe(32)
    token = _store_ceremony(
        request, "device-register", {"challenge": challenge}, handle=handle
    )
    return web.json_response(
        {"ceremony": token, "handle": handle, "challenge": challenge}
    )


async def device_register_complete(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    host: HostNode = request.app["host"]
    body = await request.json()
    ceremony = _take_ceremony(request, body.get("ceremony", ""), "device-register")
    if ceremony is None:
        return _json_error(400, "Unknown or expired ceremony")
    try:
        device_pub = base64.b64decode(body["device_pub"])
        signature = base64.b64decode(body["signature"])
        identity_pub = base64.b64decode(body["identity_pub"])
        _verify_device_signature(
            device_pub, signature, ceremony["state"]["challenge"]
        )
        upa = host.user_upa(identity_pub)
    except Exception as exc:
        return _json_error(400, f"Registration failed: {exc}")

    cred_id = DEVICE_CRED_PREFIX + device_pub
    if db.get_credential(cred_id) is not None:
        return _json_error(409, "This device key is already registered")
    user_id = db.create_user(ceremony["handle"], upa, identity_pub)
    db.add_credential(user_id, cred_id, device_pub, 0)
    host.bootstrap_contact(user_id)
    token = db.create_auth_session(user_id)
    request.app["announce"](
        f"[users] new tenant {ceremony['handle']} onboarded "
        "(device-key fallback, zero data)"
    )
    response = web.json_response(
        {"token": token, **_user_json(db.get_user(user_id), host, db)}
    )
    _set_session(response, token)
    return response


async def device_login_begin(request: web.Request) -> web.Response:
    challenge = secrets.token_urlsafe(32)
    token = _store_ceremony(request, "device-login", {"challenge": challenge})
    return web.json_response({"ceremony": token, "challenge": challenge})


async def device_login_complete(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    host: HostNode = request.app["host"]
    body = await request.json()
    ceremony = _take_ceremony(request, body.get("ceremony", ""), "device-login")
    if ceremony is None:
        return _json_error(400, "Unknown or expired ceremony")
    try:
        device_pub = base64.b64decode(body["device_pub"])
        signature = base64.b64decode(body["signature"])
        _verify_device_signature(
            device_pub, signature, ceremony["state"]["challenge"]
        )
    except Exception as exc:
        return _json_error(401, f"Authentication failed: {exc}")

    stored = db.get_credential(DEVICE_CRED_PREFIX + device_pub)
    if stored is None:
        return _json_error(401, "Unknown device key")
    user = db.get_user(stored["user_id"])
    token = db.create_auth_session(user["id"])
    response = web.json_response({"token": token, **_user_json(user, host, db)})
    _set_session(response, token)
    return response


async def logout(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        db.delete_auth_session(token)
    response = web.json_response({"ok": True})
    response.del_cookie(SESSION_COOKIE)
    return response


async def me(request: web.Request) -> web.Response:
    user = _require_user(request)
    return web.json_response(
        _user_json(user, request.app["host"], request.app["db"])
    )


# ---------------------------------------------------------------------------
# Vault (PRF-encrypted key blobs — opaque to the host)
# ---------------------------------------------------------------------------

async def vault_get(request: web.Request) -> web.Response:
    user = _require_user(request)
    blob = request.app["db"].get_vault(user["id"])
    if blob is None:
        return _json_error(404, "No vault stored")
    return web.json_response(blob)


async def vault_put(request: web.Request) -> web.Response:
    user = _require_user(request)
    blob = await request.json()
    if not isinstance(blob, dict) or "ct" not in blob or "iv" not in blob:
        return _json_error(400, "Vault blob must carry 'ct' and 'iv'")
    request.app["db"].put_vault(user["id"], blob)
    return web.json_response({"ok": True})


# ---------------------------------------------------------------------------
# Contacts
# ---------------------------------------------------------------------------

async def contacts_list(request: web.Request) -> web.Response:
    user = _require_user(request)
    rows = request.app["db"].list_contacts(user["id"])
    return web.json_response(
        [
            {"id": r["id"], "name": r["name"], "upa": r["upa"],
             "is_host": bool(r["is_host"])}
            for r in rows
        ]
    )


async def contacts_add(request: web.Request) -> web.Response:
    user = _require_user(request)
    body = await request.json()
    upa = (body.get("upa") or "").strip().lower()
    name = (body.get("name") or "").strip() or "Contact"
    try:
        parse_upa(upa)
    except ValueError as exc:
        return _json_error(400, f"Invalid UPA: {exc}")
    try:
        contact_id = request.app["db"].add_contact(user["id"], name, upa)
    except Exception:
        return _json_error(409, "Contact with this UPA already exists")
    return web.json_response({"id": contact_id, "name": name, "upa": upa})


# ---------------------------------------------------------------------------
# Prekey bundles
# ---------------------------------------------------------------------------

async def bundle_get(request: web.Request) -> web.Response:
    """Fetches a one-time prekey bundle for any UPA hosted on this node."""
    _require_user(request)
    db: Database = request.app["db"]
    host: HostNode = request.app["host"]
    upa = (request.query.get("upa") or "").strip().lower()
    if upa == host.upa:
        return web.json_response(host.publish_prekey_bundle())
    target = db.get_user_by_upa(upa)
    if target is None:
        return _json_error(404, "No such UPA on this host")
    prekey = db.take_user_prekey(target["id"])
    if prekey is None:
        return _json_error(409, "Peer has no unused prekey bundles")
    return web.json_response(prekey)


async def prekeys_publish(request: web.Request) -> web.Response:
    """Publishes client-generated public prekey bundles. Their private
    halves never leave the client's vault."""
    user = _require_user(request)
    db: Database = request.app["db"]
    body = await request.json()
    bundles = body.get("bundles", [])
    if not isinstance(bundles, list) or not bundles:
        return _json_error(400, "Expected a non-empty 'bundles' list")
    ids = [db.add_user_prekey(user["id"], bundle) for bundle in bundles]
    return web.json_response(
        {"prekey_ids": ids, "unused": db.count_user_prekeys(user["id"])}
    )


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

async def messages_list(request: web.Request) -> web.Response:
    user = _require_user(request)
    db: Database = request.app["db"]
    try:
        contact_id = int(request.query.get("contact_id", ""))
    except ValueError:
        return _json_error(400, "contact_id required")
    if db.get_contact(user["id"], contact_id) is None:
        return _json_error(404, "Unknown contact")
    rows = db.list_messages(user["id"], contact_id)
    return web.json_response(
        [
            {
                "id": r["id"],
                "direction": r["direction"],
                "envelope": json.loads(r["envelope"]) if r["envelope"] else None,
                "archive": json.loads(r["archive"]) if r["archive"] else None,
                "created_at": r["created_at"],
                "read": bool(r["read"]),
            }
            for r in rows
        ]
    )


async def messages_send(request: web.Request) -> web.Response:
    user = _require_user(request)
    db: Database = request.app["db"]
    host: HostNode = request.app["host"]
    body = await request.json()
    contact = db.get_contact(user["id"], int(body.get("contact_id", 0)))
    if contact is None:
        return _json_error(404, "Unknown contact")
    envelope = body.get("envelope")
    if not isinstance(envelope, dict) or "ciphertext" not in envelope:
        return _json_error(400, "Missing Triple Ratchet envelope")
    archive = body.get("archive")

    # The sender's own copy (vault-encrypted archive, opaque to the host)
    sent_id = db.add_message(
        user["id"], contact["id"], "out", envelope=None, archive=archive
    )

    if contact["is_host"]:
        try:
            plaintext = host.receive_envelope(
                user["id"], envelope, prekey_id=body.get("prekey_id")
            )
        except Exception as exc:
            return _json_error(400, f"Host could not decrypt: {exc}")
        reply_env = host.send_message(user["id"], host.compose_reply(plaintext))
        reply_id = db.add_message(
            user["id"], contact["id"], "in", envelope=reply_env
        )
        await _notify(
            request.app, user["id"],
            {"type": "message", "contact_id": contact["id"], "message_id": reply_id},
        )
        return web.json_response({"id": sent_id, "delivery": "host"})

    # Blind routing to another UPA
    try:
        contact_host_onion, _ = parse_upa(contact["upa"])
    except ValueError as exc:
        return _json_error(400, f"Contact UPA invalid: {exc}")
    if contact_host_onion != host.onion:
        # Remote federation over Tor is the next milestone; queue locally.
        return web.json_response({"id": sent_id, "delivery": "queued-remote"})

    recipient = db.get_user_by_upa(contact["upa"])
    if recipient is None:
        return _json_error(404, "Recipient UPA not found on this host")
    if body.get("prekey_id") is not None:
        envelope = {**envelope, "prekey_id": body["prekey_id"]}

    # Find or auto-provision the sender's entry in the recipient's contacts
    sender_entry = next(
        (c for c in db.list_contacts(recipient["id"]) if c["upa"] == user["upa"]),
        None,
    )
    if sender_entry is None:
        entry_id = db.add_contact(recipient["id"], user["handle"], user["upa"])
    else:
        entry_id = sender_entry["id"]
    delivered_id = db.add_message(
        recipient["id"], entry_id, "in", envelope=envelope
    )
    await _notify(
        request.app, recipient["id"],
        {"type": "message", "contact_id": entry_id, "message_id": delivered_id},
    )
    return web.json_response({"id": sent_id, "delivery": "local"})


async def message_archive(request: web.Request) -> web.Response:
    """The client consumed a transit envelope; replace it with the client's
    vault-encrypted archive (the plaintext-bearing envelope is destroyed)."""
    user = _require_user(request)
    db: Database = request.app["db"]
    message_id = int(request.match_info["message_id"])
    if db.get_message(user["id"], message_id) is None:
        return _json_error(404, "Unknown message")
    archive = await request.json()
    if not isinstance(archive, dict) or "ct" not in archive:
        return _json_error(400, "Archive blob must carry 'ct'")
    db.archive_message(message_id, archive)
    return web.json_response({"ok": True})


# ---------------------------------------------------------------------------
# Self-hosting migration
# ---------------------------------------------------------------------------

async def migrate(request: web.Request) -> web.Response:
    user = _require_user(request)
    db: Database = request.app["db"]
    host: HostNode = request.app["host"]
    tor = request.app["tor_options"]
    try:
        result = promote_to_sovereign(
            db,
            host,
            user["id"],
            announce=request.app["announce"],
            control_port=tor.get("control_port", 9051),
            tor_password=tor.get("password"),
            local_port=tor.get("local_port", 8000),
            start_tor_service=request.app["start_tor_on_migration"],
        )
    except ValueError as exc:
        return _json_error(400, str(exc))
    return web.json_response(result)


# ---------------------------------------------------------------------------
# WebSocket push
# ---------------------------------------------------------------------------

async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
    user = _require_user(request)
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)
    connections = request.app["ws_connections"].setdefault(user["id"], set())
    connections.add(ws)
    try:
        async for msg in ws:
            if msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                break
    finally:
        connections.discard(ws)
    return ws
