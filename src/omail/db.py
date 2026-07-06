"""
SQLite persistence for an OMail node.

Zero-knowledge storage rules:
  - The node NEVER stores user private keys or plaintext messages.
  - User key material lives only inside `vaults` as AES-GCM blobs encrypted
    client-side with a key derived from the passkey's WebAuthn PRF output.
  - Message bodies are stored either as Triple Ratchet transit envelopes
    (until the client consumes them) or as client-side vault-key-encrypted
    archives. Both are opaque to the host.
  - Host-side data (the host node's own identity and its ratchet sessions)
    is the host's own material and is stored directly.
"""
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    handle       TEXT NOT NULL UNIQUE,       -- opaque, random; no personal data
    upa          TEXT NOT NULL UNIQUE,
    identity_pub BLOB NOT NULL,              -- raw Ed25519 public key
    sovereign    INTEGER NOT NULL DEFAULT 0, -- 1 after self-hosting migration
    created_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,
    public_key    BLOB NOT NULL,             -- COSE key, CBOR-encoded
    sign_count    INTEGER NOT NULL DEFAULT 0,
    created_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS vaults (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    blob       TEXT NOT NULL,                -- PRF-encrypted JSON blob
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS contacts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    upa        TEXT NOT NULL,
    is_host    INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    UNIQUE (user_id, upa)
);
CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    direction  TEXT NOT NULL CHECK (direction IN ('in', 'out')),
    envelope   TEXT,                         -- transit Triple Ratchet envelope
    archive    TEXT,                         -- client vault-encrypted archive
    created_at REAL NOT NULL,
    read       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS host_prekeys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle     TEXT NOT NULL,                -- published PrekeyBundle JSON
    keys       TEXT NOT NULL,                -- matching ResponderKeys JSON
    used       INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS user_prekeys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bundle     TEXT NOT NULL,                -- public PrekeyBundle JSON only;
    used       INTEGER NOT NULL DEFAULT 0,   -- private halves stay in the vault
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS host_sessions (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    state   TEXT NOT NULL                    -- host-side TripleRatchet state
);
-- Per-relationship inbound slots (see docs/concepts.md). Each row is an
-- address minted on THIS host, owned by a local user, reserved for one
-- correspondent. inbound_upa is what the peer sends TO (lives here);
-- outbound_upa is the reverse address the peer minted on their host for us
-- (null until the connect handshake completes). The slot's private keys
-- never touch the server: only public prekey bundles are stored, in
-- relationship_prekeys, exactly as user_prekeys works for identities.
CREATE TABLE IF NOT EXISTS relationships (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label        TEXT NOT NULL,              -- local-only name for the correspondent
    inbound_upa  TEXT NOT NULL UNIQUE,       -- slot the peer sends to (on this host)
    outbound_upa TEXT,                        -- address we send to (peer's host)
    state        TEXT NOT NULL DEFAULT 'invited',  -- invited | connected
    created_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS relationship_prekeys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    relationship_id INTEGER NOT NULL REFERENCES relationships(id) ON DELETE CASCADE,
    bundle          TEXT NOT NULL,           -- public PrekeyBundle JSON only
    used            INTEGER NOT NULL DEFAULT 0,
    created_at      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
"""


class Database:
    """Thin synchronous wrapper around the node's SQLite store."""

    def __init__(self, path: str | Path = "data/omail.db") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # -- config -----------------------------------------------------------

    def get_config(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self.conn.execute(
            "SELECT value FROM config WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_config(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO config (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self.conn.commit()

    # -- users ------------------------------------------------------------

    def create_user(self, handle: str, upa: str, identity_pub: bytes) -> int:
        cur = self.conn.execute(
            "INSERT INTO users (handle, upa, identity_pub, created_at) "
            "VALUES (?, ?, ?, ?)",
            (handle, upa, identity_pub, time.time()),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_user(self, user_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()

    def get_user_by_handle(self, handle: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM users WHERE handle = ?", (handle,)
        ).fetchone()

    def get_user_by_upa(self, upa: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM users WHERE upa = ?", (upa,)
        ).fetchone()

    def list_users(self) -> List[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM users ORDER BY id").fetchall()

    def update_user_upa(self, user_id: int, upa: str, sovereign: bool) -> None:
        self.conn.execute(
            "UPDATE users SET upa = ?, sovereign = ? WHERE id = ?",
            (upa, int(sovereign), user_id),
        )
        self.conn.commit()

    # -- credentials --------------------------------------------------------

    def add_credential(
        self, user_id: int, credential_id: bytes, public_key: bytes, sign_count: int
    ) -> None:
        self.conn.execute(
            "INSERT INTO credentials (user_id, credential_id, public_key, "
            "sign_count, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, credential_id, public_key, sign_count, time.time()),
        )
        self.conn.commit()

    def get_credential(self, credential_id: bytes) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)
        ).fetchone()

    def list_credentials(self, user_id: int) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM credentials WHERE user_id = ?", (user_id,)
        ).fetchall()

    def update_sign_count(self, credential_id: bytes, sign_count: int) -> None:
        self.conn.execute(
            "UPDATE credentials SET sign_count = ? WHERE credential_id = ?",
            (sign_count, credential_id),
        )
        self.conn.commit()

    # -- vaults (PRF-encrypted key blobs) -----------------------------------

    def put_vault(self, user_id: int, blob: Dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO vaults (user_id, blob, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET blob = excluded.blob, "
            "updated_at = excluded.updated_at",
            (user_id, json.dumps(blob), time.time()),
        )
        self.conn.commit()

    def get_vault(self, user_id: int) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT blob FROM vaults WHERE user_id = ?", (user_id,)
        ).fetchone()
        return json.loads(row["blob"]) if row else None

    # -- contacts -----------------------------------------------------------

    def add_contact(
        self, user_id: int, name: str, upa: str, is_host: bool = False
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO contacts (user_id, name, upa, is_host, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, name, upa, int(is_host), time.time()),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_contacts(self, user_id: int) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM contacts WHERE user_id = ? ORDER BY id", (user_id,)
        ).fetchall()

    def get_contact(self, user_id: int, contact_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM contacts WHERE user_id = ? AND id = ?",
            (user_id, contact_id),
        ).fetchone()

    def get_host_contact(self, user_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM contacts WHERE user_id = ? AND is_host = 1", (user_id,)
        ).fetchone()

    def update_contact_upa(self, contact_id: int, upa: str) -> None:
        self.conn.execute(
            "UPDATE contacts SET upa = ? WHERE id = ?", (upa, contact_id)
        )
        self.conn.commit()

    def rename_host_contacts(self, name: str, *, old_name: str) -> int:
        """Renames auto-provisioned host contacts still carrying an outdated
        default label (e.g. after the 'Host Node' -> 'Administrator' rename).
        Leaves any tenant-customised name alone. Returns rows updated."""
        cur = self.conn.execute(
            "UPDATE contacts SET name = ? WHERE is_host = 1 AND name = ?",
            (name, old_name),
        )
        self.conn.commit()
        return cur.rowcount

    # -- relationships (per-relationship inbound slots) --------------------

    def create_relationship(
        self, owner_id: int, label: str, inbound_upa: str
    ) -> int:
        """Mints a local user's inbound slot for one correspondent."""
        cur = self.conn.execute(
            "INSERT INTO relationships (owner_id, label, inbound_upa, "
            "state, created_at) VALUES (?, ?, ?, 'invited', ?)",
            (owner_id, label, inbound_upa, time.time()),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_relationship(self, owner_id: int, rel_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM relationships WHERE owner_id = ? AND id = ?",
            (owner_id, rel_id),
        ).fetchone()

    def get_relationship_by_inbound_upa(self, upa: str) -> Optional[sqlite3.Row]:
        """Routing lookup: which local relationship owns this inbound slot."""
        return self.conn.execute(
            "SELECT * FROM relationships WHERE inbound_upa = ?", (upa,)
        ).fetchone()

    def list_relationships(self, owner_id: int) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM relationships WHERE owner_id = ? ORDER BY id",
            (owner_id,),
        ).fetchall()

    def connect_relationship(self, rel_id: int, outbound_upa: str) -> None:
        """Records the reverse address the peer minted for us and marks the
        relationship connected (completes the two-step handshake)."""
        self.conn.execute(
            "UPDATE relationships SET outbound_upa = ?, state = 'connected' "
            "WHERE id = ?",
            (outbound_upa, rel_id),
        )
        self.conn.commit()

    def add_relationship_prekey(self, relationship_id: int, bundle: Dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO relationship_prekeys (relationship_id, bundle, "
            "created_at) VALUES (?, ?, ?)",
            (relationship_id, json.dumps(bundle), time.time()),
        )
        self.conn.commit()
        return cur.lastrowid

    def take_relationship_prekey(self, relationship_id: int) -> Optional[Dict]:
        """Claims one unused prekey bundle for a slot (marks it used)."""
        row = self.conn.execute(
            "SELECT id, bundle FROM relationship_prekeys "
            "WHERE relationship_id = ? AND used = 0 ORDER BY id LIMIT 1",
            (relationship_id,),
        ).fetchone()
        if row is None:
            return None
        self.conn.execute(
            "UPDATE relationship_prekeys SET used = 1 WHERE id = ?", (row["id"],)
        )
        self.conn.commit()
        return json.loads(row["bundle"])

    def count_relationship_prekeys(self, relationship_id: int) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM relationship_prekeys "
            "WHERE relationship_id = ? AND used = 0",
            (relationship_id,),
        ).fetchone()["n"]

    # -- messages -----------------------------------------------------------

    def add_message(
        self,
        user_id: int,
        contact_id: int,
        direction: str,
        envelope: Optional[Dict[str, Any]] = None,
        archive: Optional[Dict[str, Any]] = None,
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO messages (user_id, contact_id, direction, envelope, "
            "archive, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                user_id,
                contact_id,
                direction,
                json.dumps(envelope) if envelope is not None else None,
                json.dumps(archive) if archive is not None else None,
                time.time(),
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_messages(self, user_id: int, contact_id: int) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM messages WHERE user_id = ? AND contact_id = ? "
            "ORDER BY id",
            (user_id, contact_id),
        ).fetchall()

    def get_message(self, user_id: int, message_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM messages WHERE user_id = ? AND id = ?",
            (user_id, message_id),
        ).fetchone()

    def archive_message(self, message_id: int, archive: Dict[str, Any]) -> None:
        """Replaces a consumed transit envelope with the client's
        vault-encrypted archive copy (the envelope is destroyed)."""
        self.conn.execute(
            "UPDATE messages SET archive = ?, envelope = NULL, read = 1 "
            "WHERE id = ?",
            (json.dumps(archive), message_id),
        )
        self.conn.commit()

    # -- host prekeys ---------------------------------------------------------

    def add_host_prekey(self, bundle: Dict[str, Any], keys: Dict[str, Any]) -> int:
        cur = self.conn.execute(
            "INSERT INTO host_prekeys (bundle, keys, created_at) VALUES (?, ?, ?)",
            (json.dumps(bundle), json.dumps(keys), time.time()),
        )
        self.conn.commit()
        return cur.lastrowid

    def take_host_prekey(self, prekey_id: int) -> Optional[Dict[str, Any]]:
        """Fetches an unused prekey's responder keys and marks it used."""
        row = self.conn.execute(
            "SELECT keys FROM host_prekeys WHERE id = ? AND used = 0", (prekey_id,)
        ).fetchone()
        if not row:
            return None
        self.conn.execute(
            "UPDATE host_prekeys SET used = 1 WHERE id = ?", (prekey_id,)
        )
        self.conn.commit()
        return json.loads(row["keys"])

    # -- user prekeys (public bundles; private halves live in the vault) --------

    def add_user_prekey(self, user_id: int, bundle: Dict[str, Any]) -> int:
        cur = self.conn.execute(
            "INSERT INTO user_prekeys (user_id, bundle, created_at) "
            "VALUES (?, ?, ?)",
            (user_id, json.dumps(bundle), time.time()),
        )
        self.conn.commit()
        return cur.lastrowid

    def take_user_prekey(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Pops one unused prekey bundle for a user (for a peer to initiate
        against). Returns {"prekey_id": id, "bundle": {...}} or None."""
        row = self.conn.execute(
            "SELECT id, bundle FROM user_prekeys WHERE user_id = ? AND used = 0 "
            "ORDER BY id LIMIT 1",
            (user_id,),
        ).fetchone()
        if not row:
            return None
        self.conn.execute(
            "UPDATE user_prekeys SET used = 1 WHERE id = ?", (row["id"],)
        )
        self.conn.commit()
        return {"prekey_id": row["id"], "bundle": json.loads(row["bundle"])}

    def count_user_prekeys(self, user_id: int) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS c FROM user_prekeys WHERE user_id = ? AND used = 0",
            (user_id,),
        ).fetchone()["c"]

    # -- host ratchet sessions -------------------------------------------------

    def put_host_session(self, user_id: int, state: Dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO host_sessions (user_id, state) VALUES (?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET state = excluded.state",
            (user_id, json.dumps(state)),
        )
        self.conn.commit()

    def get_host_session(self, user_id: int) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT state FROM host_sessions WHERE user_id = ?", (user_id,)
        ).fetchone()
        return json.loads(row["state"]) if row else None

    # -- auth sessions ----------------------------------------------------------

    def create_auth_session(
        self, user_id: int, ttl_seconds: float = 12 * 3600
    ) -> str:
        token = os.urandom(32).hex()
        now = time.time()
        self.conn.execute(
            "INSERT INTO auth_sessions (token, user_id, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (token, user_id, now, now + ttl_seconds),
        )
        self.conn.commit()
        return token

    def get_auth_session(self, token: str) -> Optional[sqlite3.Row]:
        row = self.conn.execute(
            "SELECT * FROM auth_sessions WHERE token = ?", (token,)
        ).fetchone()
        if row and row["expires_at"] < time.time():
            self.delete_auth_session(token)
            return None
        return row

    def delete_auth_session(self, token: str) -> None:
        self.conn.execute("DELETE FROM auth_sessions WHERE token = ?", (token,))
        self.conn.commit()
