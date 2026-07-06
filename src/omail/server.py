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
from omail.federation import (
    FederationClient,
    FederationError,
    bundle_core,
    connect_core,
    deliver_core,
)
from omail.host import HostNode
from omail.migration import promote_to_sovereign
from omail.upa import derive_upa, parse_upa
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

    async def _fed_notify(user_id: int, payload: dict) -> None:
        await _notify(app, user_id, payload)

    # Sending side of federation. When a Tor SOCKS port is configured we can
    # reach peer onions; otherwise only the same-host fast path works (and
    # tests inject their own transport).
    remote = None
    socks_port = (tor_options or {}).get("socks_port")
    if socks_port is not None:
        from omail.federation import tor_remote_transport
        remote = tor_remote_transport(socks_port)
    app["federation"] = FederationClient(
        db, host, notify=_fed_notify, remote=remote
    )

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
    app.router.add_get("/api/relationships", relationships_list)
    app.router.add_post("/api/relationships", relationships_create)
    app.router.add_post("/api/relationships/accept", relationships_accept)
    app.router.add_post("/api/guests", guests_create)
    app.router.add_get("/api/guests", guests_list)
    app.router.add_post("/api/guests/claim/webauthn/begin", guest_claim_webauthn_begin)
    app.router.add_post("/api/guests/claim/webauthn/complete", guest_claim_webauthn_complete)
    app.router.add_post("/api/guests/claim/devicekey/begin", guest_claim_devicekey_begin)
    app.router.add_post("/api/guests/claim/devicekey/complete", guest_claim_devicekey_complete)
    app.router.add_get("/api/credentials", credentials_list)
    app.router.add_post("/api/devices/link/begin", device_link_begin)
    app.router.add_post("/api/devices/link/deliver", device_link_deliver)
    app.router.add_get("/api/devices/link/fetch", device_link_fetch)
    app.router.add_post("/api/devices/link/claim/webauthn/begin", device_link_claim_webauthn_begin)
    app.router.add_post("/api/devices/link/claim/webauthn/complete", device_link_claim_webauthn_complete)
    app.router.add_post("/api/devices/link/claim/devicekey/begin", device_link_claim_devicekey_begin)
    app.router.add_post("/api/devices/link/claim/devicekey/complete", device_link_claim_devicekey_complete)
    app.router.add_post("/api/federation/connect", federation_connect)
    app.router.add_get("/api/federation/bundle", federation_bundle)
    app.router.add_post("/api/federation/deliver", federation_deliver)
    app.router.add_get("/api/bundle", bundle_get)
    app.router.add_post("/api/prekeys", prekeys_publish)
    app.router.add_get("/api/messages", messages_list)
    app.router.add_post("/api/messages/send", messages_send)
    app.router.add_post("/api/messages/{message_id}/archive", message_archive)
    app.router.add_post("/api/migrate", migrate)
    app.router.add_get("/api/ws", websocket_handler)

    static_dir = resources.files("omail") / "static"
    app.router.add_static("/static/", path=str(static_dir), name="static")

    # Registered last so it only ever catches paths nothing above matched.
    app.router.add_get("/{path:.+}", portal_fallback)
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


def _ws_notify(request: web.Request):
    """A notify callback bound to this request's app, for handlers that
    aren't already inside one (federation_deliver builds its own inline)."""
    async def notify(user_id: int, payload: dict) -> None:
        await _notify(request.app, user_id, payload)
    return notify


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


_NOT_A_WEBPAGE_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Not a webpage — {host_name} OMail</title>
<style>body{{font-family:sans-serif;max-width:40em;margin:4em auto;
padding:0 1.5em;line-height:1.5}}code{{background:#eee;padding:.2em .4em;
border-radius:3px;word-break:break-all}}</style></head><body>
<h2>This is an address, not a webpage.</h2>
<p><code>{upa}</code> is a User Privacy Address — a private routing
address for OMail, not a page to load. Paste it into your <strong>own</strong>
OMail client's "Accept invite" box to message this account; don't open it
directly in a browser.</p>
<p><a href="/">Open the {host_name} OMail portal</a></p>
</body></html>"""


async def portal_fallback(request: web.Request) -> web.Response:
    """A UPA is a bearer address to paste into an OMail client, not a URL to
    open — except a guest's invite, which IS meant to be opened directly.
    People naturally share "just the address" (that's how peer UPAs work
    too), so a bare, un-prefixed guest link should still work: redirect it
    into the ?claim= flow. For anything else that merely looks like a valid
    UPA on this host, explain instead of a bare 404."""
    db: Database = request.app["db"]
    host: HostNode = request.app["host"]
    path = request.match_info.get("path", "")
    upa = f"{host.onion}/{path}".strip().lower()
    try:
        parse_upa(upa)
    except ValueError:
        raise web.HTTPNotFound()

    invite = db.get_guest_invite_by_upa(upa)
    if invite is not None and invite["claimed_user_id"] is None:
        raise web.HTTPFound(f"/?claim={upa}")

    html = _NOT_A_WEBPAGE_HTML.format(upa=upa, host_name=host.host_name)
    return web.Response(text=html, content_type="text/html", status=404)


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
# Credentials & multi-device linking.
#
# Copying an identity to a new device is a deliberate, explicit action, not
# a side effect of re-presenting any invite: the already-authenticated
# device creates a short-lived link and uploads an encrypted parcel (vault
# contents encrypted client-side with a link_secret transmitted only via the
# out-of-band QR/URL fragment — the server never sees link_secret or
# plaintext). The new device fetches the opaque parcel, decrypts it
# locally, then registers its own credential bound to the link.
# ---------------------------------------------------------------------------

def _credential_json(row) -> dict:
    raw = bytes(row["credential_id"])
    is_device_key = raw.startswith(DEVICE_CRED_PREFIX)
    return {
        "id": base64.b64encode(raw).decode(),
        "kind": "device-key" if is_device_key else "passkey",
        "created_at": row["created_at"],
    }


async def credentials_list(request: web.Request) -> web.Response:
    user = _require_user(request)
    rows = request.app["db"].list_credentials(user["id"])
    return web.json_response([_credential_json(r) for r in rows])


async def device_link_begin(request: web.Request) -> web.Response:
    user = _require_user(request)
    db: Database = request.app["db"]
    link_id = secrets.token_urlsafe(24)
    db.create_device_link(link_id, user["id"])
    return web.json_response({"link_id": link_id})


async def device_link_deliver(request: web.Request) -> web.Response:
    """The source device uploads the encrypted parcel once it has minted
    the link. Restricted to the same user the link belongs to."""
    user = _require_user(request)
    db: Database = request.app["db"]
    body = await request.json()
    link_id = (body.get("link_id") or "").strip()
    link = db.get_device_link(link_id)
    if link is None or link["user_id"] != user["id"]:
        return _json_error(404, "Unknown or expired link")
    if link["consumed_user_id"] is not None:
        return _json_error(409, "Link already used")
    parcel = body.get("parcel")
    if not isinstance(parcel, dict) or "ct" not in parcel or "iv" not in parcel:
        return _json_error(400, "Parcel must be an encrypted blob")
    db.set_device_link_parcel(link_id, json.dumps(parcel))
    return web.json_response({"ok": True})


async def device_link_fetch(request: web.Request) -> web.Response:
    """Unauthenticated: the new device has no session yet. Gated by the
    short-lived, single-use link_id; the parcel itself is opaque
    ciphertext the server cannot decrypt."""
    db: Database = request.app["db"]
    link_id = (request.query.get("link_id") or "").strip()
    link = db.get_device_link(link_id)
    if link is None:
        return _json_error(404, "Unknown or expired link")
    if link["consumed_user_id"] is not None:
        return _json_error(410, "Link already used")
    if link["parcel"] is None:
        return web.json_response({"ready": False})
    return web.json_response({"ready": True, "parcel": json.loads(link["parcel"])})


def _pending_link(db: Database, link_id: str):
    link = db.get_device_link(link_id)
    if link is None:
        return None, _json_error(404, "Unknown or expired link")
    if link["consumed_user_id"] is not None:
        return None, _json_error(410, "Link already used")
    return link, None


async def device_link_claim_webauthn_begin(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    body = await request.json()
    link_id = (body.get("link_id") or "").strip()
    link, err = _pending_link(db, link_id)
    if err:
        return err
    target = db.get_user(link["user_id"])
    user_id_bytes = os.urandom(16)
    options, state = _passkeys(request).begin_registration(target["handle"], user_id_bytes)
    token = _store_ceremony(
        request, "device-link-claim", state,
        link_id=link_id, target_user_id=link["user_id"],
    )
    return web.json_response(
        {"ceremony": token, "options": json.loads(json.dumps(options, default=str))}
    )


async def device_link_claim_webauthn_complete(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    host: HostNode = request.app["host"]
    body = await request.json()
    ceremony = _take_ceremony(request, body.get("ceremony", ""), "device-link-claim")
    if ceremony is None:
        return _json_error(400, "Unknown or expired ceremony")
    link, err = _pending_link(db, ceremony["link_id"])
    if err:
        return err
    try:
        cred_id, cred_blob, sign_count = _passkeys(request).complete_registration(
            ceremony["state"], body["credential"]
        )
    except Exception as exc:
        return _json_error(400, f"Registration failed: {exc}")

    db.add_credential(link["user_id"], cred_id, cred_blob, sign_count)
    db.consume_device_link(ceremony["link_id"], link["user_id"])
    token = db.create_auth_session(link["user_id"])
    response = web.json_response(
        {"token": token, **_user_json(db.get_user(link["user_id"]), host, db)}
    )
    _set_session(response, token)
    return response


async def device_link_claim_devicekey_begin(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    body = await request.json()
    link_id = (body.get("link_id") or "").strip()
    link, err = _pending_link(db, link_id)
    if err:
        return err
    challenge = secrets.token_urlsafe(32)
    token = _store_ceremony(
        request, "device-link-claim-device", {"challenge": challenge},
        link_id=link_id, target_user_id=link["user_id"],
    )
    return web.json_response({"ceremony": token, "challenge": challenge})


async def device_link_claim_devicekey_complete(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    host: HostNode = request.app["host"]
    body = await request.json()
    ceremony = _take_ceremony(
        request, body.get("ceremony", ""), "device-link-claim-device"
    )
    if ceremony is None:
        return _json_error(400, "Unknown or expired ceremony")
    link, err = _pending_link(db, ceremony["link_id"])
    if err:
        return err
    try:
        device_pub = base64.b64decode(body["device_pub"])
        signature = base64.b64decode(body["signature"])
        _verify_device_signature(
            device_pub, signature, ceremony["state"]["challenge"]
        )
    except Exception as exc:
        return _json_error(400, f"Authentication failed: {exc}")

    cred_id = DEVICE_CRED_PREFIX + device_pub
    if db.get_credential(cred_id) is not None:
        return _json_error(409, "This device key is already registered")
    db.add_credential(link["user_id"], cred_id, device_pub, 0)
    db.consume_device_link(ceremony["link_id"], link["user_id"])
    token = db.create_auth_session(link["user_id"])
    response = web.json_response(
        {"token": token, **_user_json(db.get_user(link["user_id"]), host, db)}
    )
    _set_session(response, token)
    return response


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
# Relationships (per-relationship inbound slots — see docs/concepts.md)
# ---------------------------------------------------------------------------

def _user_onion(user) -> str:
    """The onion a NEW relationship/guest slot should be minted under for
    this user: their own sovereign onion once they've migrated, or the
    shared node onion before that — both are already encoded in
    user['upa'], so no separate lookup is needed. Using host.onion
    unconditionally here would keep vending addresses under the node's
    shared identity even after a tenant becomes sovereign, defeating the
    point of migrating (see docs/concepts.md graduation flow)."""
    onion, _ = parse_upa(user["upa"])
    return onion


def _relationship_json(row) -> dict:
    return {
        "id": row["id"],
        "label": row["label"],
        "inbound_upa": row["inbound_upa"],
        "outbound_upa": row["outbound_upa"],
        "contact_id": row["contact_id"],
        "state": row["state"],
    }


async def relationships_list(request: web.Request) -> web.Response:
    user = _require_user(request)
    rows = request.app["db"].list_relationships(user["id"])
    return web.json_response([_relationship_json(r) for r in rows])


async def relationships_create(request: web.Request) -> web.Response:
    """Mints ONE unified invite for a correspondent — usable either way,
    decided by them, not by Alice up front:

      - pasted into their OWN host's "Accept invite" box, it runs the
        ordinary federation connect handshake (see relationships_accept);
      - opened directly as a URL with no host of their own, it becomes a
        guest claim (see guest_claim_*_complete).

    Both paths share the exact same inbound_upa. The client generates the
    slot keypair (private half stays in its vault) and posts the slot's
    public key plus public prekey bundles — needed up front so a peer can
    initiate a session immediately; a browser-only claimant simply never
    touches this slot's keys and mints their own independent identity
    instead. Whichever path happens first wins; see the mutual-exclusion
    checks in connect_core and the guest claim handlers."""
    user = _require_user(request)
    db: Database = request.app["db"]
    body = await request.json()
    label = (body.get("label") or "").strip() or "Contact"
    try:
        slot_pub = base64.b64decode(body["slot_pub"])
        inbound_upa = derive_upa(_user_onion(user), slot_pub)
    except Exception as exc:
        return _json_error(400, f"Invalid slot key: {exc}")
    bundles = body.get("bundles", [])
    if not isinstance(bundles, list) or not bundles:
        return _json_error(400, "Expected a non-empty 'bundles' list")
    try:
        rel_id = db.create_relationship(user["id"], label, inbound_upa)
    except Exception:
        return _json_error(409, "That slot address is already in use")
    prekey_ids = [db.add_relationship_prekey(rel_id, bundle) for bundle in bundles]
    # Register the same address as a guest claim, so whoever receives this
    # invite can use either path without Alice choosing in advance.
    db.create_guest_invite(user["id"], label, inbound_upa)
    result = _relationship_json(db.get_relationship(user["id"], rel_id))
    result["prekey_ids"] = prekey_ids
    result["claim_url"] = f"/?claim={inbound_upa}"
    return web.json_response(result)


async def relationships_accept(request: web.Request) -> web.Response:
    """Accept an invite. The client mints a reverse slot (its own inbound
    address for this correspondent) and posts its public key + prekey
    bundles plus the invite it received. We create the local relationship
    and thread, publish the reverse slot's bundles, then run the connect
    handshake against the inviter's host so both sides are bound."""
    user = _require_user(request)
    db: Database = request.app["db"]
    fed: FederationClient = request.app["federation"]
    body = await request.json()
    label = (body.get("label") or "").strip() or "Contact"
    invite_upa = (body.get("invite_upa") or "").strip().lower()
    try:
        parse_upa(invite_upa)
        slot_pub = base64.b64decode(body["slot_pub"])
        reverse_upa = derive_upa(_user_onion(user), slot_pub)
    except Exception as exc:
        return _json_error(400, f"Invalid invite or slot key: {exc}")
    bundles = body.get("bundles", [])
    if not isinstance(bundles, list) or not bundles:
        return _json_error(400, "Expected a non-empty 'bundles' list")

    contact_id = db.add_contact(user["id"], label, invite_upa)
    try:
        rel_id = db.create_relationship(user["id"], label, reverse_upa)
    except Exception:
        return _json_error(409, "That slot address is already in use")
    db.set_relationship_contact(rel_id, contact_id)
    prekey_ids = [db.add_relationship_prekey(rel_id, b) for b in bundles]

    try:
        await fed.connect(invite_upa, reverse_upa)
    except FederationError as exc:
        return _json_error(exc.status, f"Connect handshake failed: {exc.message}")
    db.connect_relationship(rel_id, invite_upa)

    result = _relationship_json(db.get_relationship(user["id"], rel_id))
    result["contact"] = {"id": contact_id, "name": label, "upa": invite_upa}
    result["prekey_ids"] = prekey_ids
    return web.json_response(result)


# ---------------------------------------------------------------------------
# Guests (see docs/concepts.md): a hosted non-OMail correspondent. The host
# mints the guest's single UPA ahead of time as a claim capability; whoever
# first presents it completes the one registration ceremony (passkey,
# falling back to device-key) that becomes their permanent credential —
# after that, the invite is spent and only the credential grants access.
# ---------------------------------------------------------------------------

def _guest_invite_json(row) -> dict:
    return {
        "id": row["id"],
        "label": row["label"],
        "inbound_upa": row["inbound_upa"],
        "claimed": row["claimed_user_id"] is not None,
    }


async def guests_create(request: web.Request) -> web.Response:
    """Mints a guest invite. The address bytes are opaque random data — not
    a real Ed25519 point — since a guest's inbound UPA only needs to be a
    validly checksummed, unlinkable capability; the guest's real Triple
    Ratchet identity is generated in their own browser at claim time."""
    user = _require_user(request)
    db: Database = request.app["db"]
    body = await request.json()
    label = (body.get("label") or "").strip() or "Guest"
    inbound_upa = derive_upa(_user_onion(user), os.urandom(32))
    invite_id = db.create_guest_invite(user["id"], label, inbound_upa)
    return web.json_response(
        {"id": invite_id, "label": label, "inbound_upa": inbound_upa, "claimed": False}
    )


async def guests_list(request: web.Request) -> web.Response:
    user = _require_user(request)
    rows = request.app["db"].list_guest_invites(user["id"])
    return web.json_response([_guest_invite_json(r) for r in rows])


async def _bind_guest_relationship(db: Database, upa: str, notify=None) -> None:
    """If this UPA was minted as a unified invite (relationships_create),
    binds it exactly the way a connecting peer would: marks the
    relationship connected and gives the inviter an automatic contact for
    the new guest (pushed live over their WebSocket, same as a peer
    connecting would), reusing connect_core so both paths behave
    identically from the inviter's side. No-ops for guests created via the
    standalone /api/guests endpoint, which has no matching relationship
    row."""
    if db.get_relationship_by_inbound_upa(upa) is None:
        return
    try:
        await connect_core(db, upa, upa, notify)
    except FederationError:
        pass  # lost a race to a real peer connecting; the guest account still stands


def _unclaimed_invite(db: Database, upa: str):
    """Guards the guest-claim path of a unified invite: rejects it if
    someone already claimed it as a guest, OR if a peer with their own host
    already connected to it first (relationships_create registers both
    paths for the same address; whichever happens first wins)."""
    invite = db.get_guest_invite_by_upa(upa)
    if invite is None:
        return None, _json_error(404, "Unknown invite")
    if invite["claimed_user_id"] is not None:
        return None, _json_error(410, "This invite has already been claimed")
    rel = db.get_relationship_by_inbound_upa(upa)
    if rel is not None and rel["state"] == "connected":
        return None, _json_error(
            410, "This invite has already been connected to another OMail host"
        )
    return invite, None


async def guest_claim_webauthn_begin(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    body = await request.json()
    upa = (body.get("inbound_upa") or "").strip().lower()
    invite, err = _unclaimed_invite(db, upa)
    if err:
        return err
    handle = new_handle()
    while db.get_user_by_handle(handle):
        handle = new_handle()
    user_id_bytes = os.urandom(16)
    options, state = _passkeys(request).begin_registration(handle, user_id_bytes)
    token = _store_ceremony(
        request, "guest-claim", state, handle=handle, inbound_upa=upa
    )
    return web.json_response(
        {"ceremony": token, "handle": handle,
         "options": json.loads(json.dumps(options, default=str))}
    )


async def guest_claim_webauthn_complete(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    host: HostNode = request.app["host"]
    body = await request.json()
    ceremony = _take_ceremony(request, body.get("ceremony", ""), "guest-claim")
    if ceremony is None:
        return _json_error(400, "Unknown or expired ceremony")
    invite, err = _unclaimed_invite(db, ceremony["inbound_upa"])
    if err:
        return err
    try:
        identity_pub = base64.b64decode(body["identity_pub"])
        cred_id, cred_blob, sign_count = _passkeys(request).complete_registration(
            ceremony["state"], body["credential"]
        )
    except Exception as exc:
        return _json_error(400, f"Registration failed: {exc}")

    user_id = db.create_user(
        ceremony["handle"], invite["inbound_upa"], identity_pub, guest=True
    )
    db.add_credential(user_id, cred_id, cred_blob, sign_count)
    host.bootstrap_contact(user_id)
    await _bind_guest_relationship(db, invite["inbound_upa"], _ws_notify(request))
    db.claim_guest_invite(invite["id"], user_id)
    token = db.create_auth_session(user_id)
    request.app["announce"](
        f"[guests] {ceremony['handle']} claimed a guest inbox (passkey)"
    )
    response = web.json_response(
        {"token": token, **_user_json(db.get_user(user_id), host, db)}
    )
    _set_session(response, token)
    return response


async def guest_claim_devicekey_begin(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    body = await request.json()
    upa = (body.get("inbound_upa") or "").strip().lower()
    invite, err = _unclaimed_invite(db, upa)
    if err:
        return err
    handle = new_handle()
    while db.get_user_by_handle(handle):
        handle = new_handle()
    challenge = secrets.token_urlsafe(32)
    token = _store_ceremony(
        request, "guest-claim-device", {"challenge": challenge},
        handle=handle, inbound_upa=upa,
    )
    return web.json_response({"ceremony": token, "handle": handle, "challenge": challenge})


async def guest_claim_devicekey_complete(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    host: HostNode = request.app["host"]
    body = await request.json()
    ceremony = _take_ceremony(request, body.get("ceremony", ""), "guest-claim-device")
    if ceremony is None:
        return _json_error(400, "Unknown or expired ceremony")
    invite, err = _unclaimed_invite(db, ceremony["inbound_upa"])
    if err:
        return err
    try:
        device_pub = base64.b64decode(body["device_pub"])
        signature = base64.b64decode(body["signature"])
        identity_pub = base64.b64decode(body["identity_pub"])
        _verify_device_signature(
            device_pub, signature, ceremony["state"]["challenge"]
        )
    except Exception as exc:
        return _json_error(400, f"Registration failed: {exc}")

    cred_id = DEVICE_CRED_PREFIX + device_pub
    if db.get_credential(cred_id) is not None:
        return _json_error(409, "This device key is already registered")
    user_id = db.create_user(
        ceremony["handle"], invite["inbound_upa"], identity_pub, guest=True
    )
    db.add_credential(user_id, cred_id, device_pub, 0)
    host.bootstrap_contact(user_id)
    await _bind_guest_relationship(db, invite["inbound_upa"], _ws_notify(request))
    db.claim_guest_invite(invite["id"], user_id)
    token = db.create_auth_session(user_id)
    request.app["announce"](
        f"[guests] {ceremony['handle']} claimed a guest inbox (device-key)"
    )
    response = web.json_response(
        {"token": token, **_user_json(db.get_user(user_id), host, db)}
    )
    _set_session(response, token)
    return response


# ---------------------------------------------------------------------------
# Federation (host-to-host; capability-authorized, no session cookie)
# ---------------------------------------------------------------------------

def _fed_error(exc: FederationError) -> web.Response:
    return web.json_response({"error": exc.message}, status=exc.status)


async def federation_connect(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    body = await request.json()
    try:
        return web.json_response(await connect_core(
            db,
            (body.get("invite_upa") or "").strip().lower(),
            (body.get("reverse_upa") or "").strip().lower(),
            _ws_notify(request),
        ))
    except FederationError as exc:
        return _fed_error(exc)


async def federation_bundle(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    try:
        return web.json_response(bundle_core(
            db, (request.query.get("upa") or "").strip().lower()
        ))
    except FederationError as exc:
        return _fed_error(exc)


async def federation_deliver(request: web.Request) -> web.Response:
    db: Database = request.app["db"]
    body = await request.json()
    envelope = body.get("envelope")
    if not isinstance(envelope, dict):
        return _json_error(400, "Missing envelope")

    try:
        return web.json_response(await deliver_core(
            db, (body.get("target_upa") or "").strip().lower(),
            envelope, _ws_notify(request),
        ))
    except FederationError as exc:
        return _fed_error(exc)


# ---------------------------------------------------------------------------
# Prekey bundles
# ---------------------------------------------------------------------------

async def bundle_get(request: web.Request) -> web.Response:
    """Fetches a one-time prekey bundle for a UPA. The Administrator and
    legacy identity UPAs resolve locally; per-relationship slots (local or
    on another host) resolve through federation."""
    _require_user(request)
    db: Database = request.app["db"]
    host: HostNode = request.app["host"]
    fed: FederationClient = request.app["federation"]
    upa = (request.query.get("upa") or "").strip().lower()
    if upa == host.upa:
        return web.json_response(host.publish_prekey_bundle())
    try:
        parse_upa(upa)
    except ValueError:
        return _json_error(404, "No such UPA")
    target = db.get_user_by_upa(upa)
    if target is not None:
        prekey = db.take_user_prekey(target["id"])
        if prekey is None:
            return _json_error(409, "Peer has no unused prekey bundles")
        return web.json_response(prekey)
    # A per-relationship slot: same-host slots and remote slots both go
    # through the federation client (which short-circuits same-host).
    try:
        return web.json_response(await fed.fetch_bundle(upa))
    except FederationError as exc:
        return _fed_error(exc)


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

    if body.get("prekey_id") is not None:
        envelope = {**envelope, "prekey_id": body["prekey_id"]}

    # Per-relationship slot: route to the peer's inbound address through
    # federation (same-host short-circuits; cross-host goes over Tor).
    rel = db.get_relationship_by_contact(user["id"], contact["id"])
    if rel is not None and rel["outbound_upa"]:
        fed: FederationClient = request.app["federation"]
        try:
            await fed.deliver(rel["outbound_upa"], envelope)
        except FederationError as exc:
            return _json_error(exc.status, f"Delivery failed: {exc.message}")
        onion, _ = parse_upa(rel["outbound_upa"])
        delivery = "local" if onion == host.onion else "federated"
        return web.json_response({"id": sent_id, "delivery": delivery})

    # Legacy blind routing to an identity UPA on this host
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
