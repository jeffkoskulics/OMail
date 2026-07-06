"""
Host-to-host federation (see docs/concepts.md).

Only three things ever cross between hosts, and they are the whole external
surface of a node's federation API:

  * connect  — the acceptor's host tells the inviter's host "I accepted your
               invite; here is my reverse inbound address."
  * bundle   — fetch a one-time prekey bundle for a slot on another host so
               the sender can initiate a Triple Ratchet session.
  * deliver  — drop an (opaque, end-to-end encrypted) envelope into a slot on
               the recipient's host.

Authorization is capability-based: to act on a slot you must know its UPA,
which was only ever shared with the one correspondent it belongs to. Each
core also verifies the addressed slot actually lives on this host.

The three cores below are pure functions over (db, host[, notify]) so they
can be invoked two ways:
  * locally, in-process, when the peer onion is this host (the same-host fast
    path, and the cheapest integration test), and
  * remotely, by the thin aiohttp routes in server.py, when another host
    calls in over Tor.

`FederationClient` is the sending side. It routes same-host calls straight to
the cores and hands remote calls to an injectable transport (wired to Tor in
Phase 2b; injected to a sibling app in tests).
"""
from typing import Awaitable, Callable, Optional

from omail.db import Database
from omail.host import HostNode
from omail.upa import parse_upa


class FederationError(Exception):
    """Carries an HTTP-ish status so routes and callers can map it back."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _host_of(upa: str) -> str:
    onion, _ = parse_upa(upa)
    return onion


# ---------------------------------------------------------------------------
# Receiving cores (run on the host that owns the addressed slot)
# ---------------------------------------------------------------------------

def connect_core(db: Database, invite_upa: str, reverse_upa: str) -> dict:
    """Inviter side: the acceptor is completing the handshake. Bind the
    reverse address to the invited relationship and mark it connected.

    Whether invite_upa is "hosted here" is decided by the DB lookup below,
    not by comparing onions: a node serves the shared host onion PLUS one
    onion per sovereign tenant it hosts, all on the same process/DB, so
    there is no single onion string to compare against.
    """
    try:
        parse_upa(reverse_upa)
    except ValueError as exc:
        raise FederationError(400, f"Invalid reverse address: {exc}")

    rel = db.get_relationship_by_inbound_upa(invite_upa)
    if rel is None:
        raise FederationError(404, "Unknown invite")
    if rel["state"] == "connected":
        if rel["outbound_upa"] == reverse_upa:
            return {"ok": True}  # idempotent re-connect
        raise FederationError(409, "Invite already connected")

    db.connect_relationship(rel["id"], reverse_upa)
    # Give the inviter a thread for this correspondent now that it is real.
    if rel["contact_id"] is None:
        contact_id = db.add_contact(rel["owner_id"], rel["label"], reverse_upa)
        db.set_relationship_contact(rel["id"], contact_id)
    return {"ok": True}


def bundle_core(db: Database, upa: str) -> dict:
    """Hand out a one-time prekey bundle for a slot that lives on this host."""
    rel = db.get_relationship_by_inbound_upa(upa)
    if rel is None:
        raise FederationError(404, "Unknown slot")
    prekey = db.take_relationship_prekey(rel["id"])
    if prekey is None:
        raise FederationError(409, "Slot has no unused prekey bundles")
    return prekey


async def deliver_core(db: Database, target_upa: str, envelope: dict,
                       notify: Optional[Callable[[int, dict], Awaitable]] = None
                       ) -> dict:
    """Route an envelope into the local inbox that owns the target slot."""
    rel = db.get_relationship_by_inbound_upa(target_upa)
    if rel is None:
        raise FederationError(404, "Unknown slot")
    contact_id = rel["contact_id"]
    if contact_id is None:
        # A message arrived before the handshake bound a thread; bind one.
        contact_id = db.add_contact(
            rel["owner_id"], rel["label"], rel["outbound_upa"] or rel["inbound_upa"]
        )
        db.set_relationship_contact(rel["id"], contact_id)
    message_id = db.add_message(
        rel["owner_id"], contact_id, "in", envelope=envelope
    )
    if notify is not None:
        await notify(rel["owner_id"],
                     {"type": "message", "contact_id": contact_id,
                      "message_id": message_id})
    return {"ok": True}


# ---------------------------------------------------------------------------
# Sending side
# ---------------------------------------------------------------------------

# A remote transport takes (peer_onion, path, json_payload) and returns the
# decoded JSON response, raising FederationError on a non-2xx reply.
RemoteTransport = Callable[[str, str, dict], Awaitable[dict]]


async def _no_remote(peer_onion: str, path: str, payload: dict) -> dict:
    raise FederationError(
        502, f"Remote federation to {peer_onion} is not configured on this node"
    )


def tor_remote_transport(socks_port: int = 9050,
                         timeout: float = 30.0) -> RemoteTransport:
    """A remote transport that reaches peer onions over Tor's SOCKS proxy.

    aiohttp-socks is imported lazily so nodes that never federate (or run
    with --no-tor) don't need it. GET is used for /bundle (payload becomes
    query params); everything else is POSTed as JSON.
    """
    async def remote(peer_onion: str, path: str, payload: dict) -> dict:
        import aiohttp
        from aiohttp_socks import ProxyConnector

        url = f"http://{peer_onion}{path}"
        connector = ProxyConnector.from_url(f"socks5h://127.0.0.1:{socks_port}")
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        try:
            async with aiohttp.ClientSession(
                connector=connector, timeout=client_timeout
            ) as session:
                if path.endswith("/bundle"):
                    ctx = session.get(url, params=payload)
                else:
                    ctx = session.post(url, json=payload)
                async with ctx as resp:
                    data = await resp.json()
                    if resp.status >= 400:
                        raise FederationError(
                            resp.status,
                            data.get("error", "federation error"),
                        )
                    return data
        except FederationError:
            raise
        except Exception as exc:  # network / Tor / decode failures
            raise FederationError(502, f"Could not reach {peer_onion}: {exc}")

    return remote


class FederationClient:
    """The sending side of federation. Same-host calls go straight to the
    cores; cross-host calls go through the injected remote transport."""

    def __init__(self, db: Database, host: HostNode,
                 notify: Optional[Callable[[int, dict], Awaitable]] = None,
                 remote: Optional[RemoteTransport] = None) -> None:
        self.db = db
        self.host = host
        self.notify = notify
        self.remote = remote or _no_remote

    def _is_self(self, onion: str) -> bool:
        """A node serves the shared host onion PLUS one onion per sovereign
        tenant it hosts, all on this same process/DB — so "local" means
        either of those, not just the node's own primary identity."""
        return onion == self.host.onion or self.db.is_sovereign_onion(onion)

    async def connect(self, invite_upa: str, reverse_upa: str) -> dict:
        onion = _host_of(invite_upa)
        if self._is_self(onion):
            return connect_core(self.db, invite_upa, reverse_upa)
        return await self.remote(
            onion, "/api/federation/connect",
            {"invite_upa": invite_upa, "reverse_upa": reverse_upa},
        )

    async def fetch_bundle(self, upa: str) -> dict:
        onion = _host_of(upa)
        if self._is_self(onion):
            return bundle_core(self.db, upa)
        return await self.remote(
            onion, "/api/federation/bundle", {"upa": upa}
        )

    async def deliver(self, target_upa: str, envelope: dict) -> dict:
        onion = _host_of(target_upa)
        if self._is_self(onion):
            return await deliver_core(
                self.db, target_upa, envelope, self.notify
            )
        return await self.remote(
            onion, "/api/federation/deliver",
            {"target_upa": target_upa, "envelope": envelope},
        )
