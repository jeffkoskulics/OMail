import time

import pytest

from omail.db import Database


@pytest.fixture
def db():
    database = Database(":memory:")
    yield database
    database.close()


@pytest.fixture
def user_id(db):
    return db.create_user("user-abc123", "host.onion/useraddr", b"\x01" * 32)


def test_config_roundtrip(db):
    assert db.get_config("mode") is None
    assert db.get_config("mode", "tenant") == "tenant"
    db.set_config("mode", "host")
    assert db.get_config("mode") == "host"
    db.set_config("mode", "tenant")
    assert db.get_config("mode") == "tenant"


def test_user_lifecycle(db, user_id):
    user = db.get_user(user_id)
    assert user["handle"] == "user-abc123"
    assert user["sovereign"] == 0
    assert db.get_user_by_handle("user-abc123")["id"] == user_id
    assert db.get_user_by_upa("host.onion/useraddr")["id"] == user_id
    assert len(db.list_users()) == 1

    db.update_user_upa(user_id, "newhost.onion/useraddr", sovereign=True)
    updated = db.get_user(user_id)
    assert updated["upa"] == "newhost.onion/useraddr"
    assert updated["sovereign"] == 1


def test_is_sovereign_onion(db, user_id):
    # Not sovereign yet: the node's shared onion isn't a *sovereign* onion
    assert db.is_sovereign_onion("host.onion") is False

    db.update_user_upa(user_id, "myown.onion/useraddr", sovereign=True)
    assert db.is_sovereign_onion("myown.onion") is True
    assert db.is_sovereign_onion("myown") is True  # suffix optional
    assert db.is_sovereign_onion("someoneelse.onion") is False


def test_duplicate_handle_rejected(db, user_id):
    with pytest.raises(Exception):
        db.create_user("user-abc123", "other.onion/x", b"\x02" * 32)


def test_credentials(db, user_id):
    db.add_credential(user_id, b"cred-1", b"cose-key", sign_count=0)
    cred = db.get_credential(b"cred-1")
    assert cred["user_id"] == user_id
    assert db.get_credential(b"missing") is None
    assert len(db.list_credentials(user_id)) == 1

    db.update_sign_count(b"cred-1", 7)
    assert db.get_credential(b"cred-1")["sign_count"] == 7


def test_vault_blob_roundtrip(db, user_id):
    assert db.get_vault(user_id) is None
    blob = {"iv": "abc", "ct": "def", "salt": "ghi"}
    db.put_vault(user_id, blob)
    assert db.get_vault(user_id) == blob
    db.put_vault(user_id, {"iv": "new", "ct": "new"})
    assert db.get_vault(user_id)["iv"] == "new"


def test_contacts(db, user_id):
    host_id = db.add_contact(user_id, "Host Node", "host.onion/hostaddr", is_host=True)
    friend_id = db.add_contact(user_id, "Ada", "other.onion/adaaddr")
    assert [c["name"] for c in db.list_contacts(user_id)] == ["Host Node", "Ada"]
    assert db.get_host_contact(user_id)["id"] == host_id
    assert db.get_contact(user_id, friend_id)["upa"] == "other.onion/adaaddr"
    assert db.get_contact(user_id, 999) is None

    db.update_contact_upa(host_id, "sovereign.onion/hostaddr")
    assert db.get_host_contact(user_id)["upa"] == "sovereign.onion/hostaddr"


def test_relationship_slot_lifecycle(db, user_id):
    # Alice mints an inbound slot reserved for "Bob"
    rel_id = db.create_relationship(user_id, "Bob", "alice.onion/bobslotkey")
    rel = db.get_relationship(user_id, rel_id)
    assert rel["label"] == "Bob"
    assert rel["inbound_upa"] == "alice.onion/bobslotkey"
    assert rel["outbound_upa"] is None
    assert rel["state"] == "invited"

    # Routing lookup by the slot address
    assert db.get_relationship_by_inbound_upa("alice.onion/bobslotkey")["id"] == rel_id
    assert db.get_relationship_by_inbound_upa("nope.onion/x") is None

    # The connect handshake records the reverse address Bob minted for us
    db.connect_relationship(rel_id, "bob.onion/aliceslotkey")
    rel = db.get_relationship(user_id, rel_id)
    assert rel["outbound_upa"] == "bob.onion/aliceslotkey"
    assert rel["state"] == "connected"

    assert [r["label"] for r in db.list_relationships(user_id)] == ["Bob"]


def test_relationship_prekeys(db, user_id):
    rel_id = db.create_relationship(user_id, "Bob", "alice.onion/bobslotkey")
    assert db.count_relationship_prekeys(rel_id) == 0

    id1 = db.add_relationship_prekey(rel_id, {"spk": "b1"})
    db.add_relationship_prekey(rel_id, {"spk": "b2"})
    assert db.count_relationship_prekeys(rel_id) == 2

    first = db.take_relationship_prekey(rel_id)
    assert first == {"prekey_id": id1, "bundle": {"spk": "b1"}}
    assert db.count_relationship_prekeys(rel_id) == 1
    assert db.take_relationship_prekey(rel_id)["bundle"] == {"spk": "b2"}
    assert db.take_relationship_prekey(rel_id) is None  # exhausted


def test_relationships_cascade_on_user_delete(db, user_id):
    rel_id = db.create_relationship(user_id, "Bob", "alice.onion/bobslotkey")
    db.add_relationship_prekey(rel_id, {"spk": "b1"})
    db.conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.conn.commit()
    assert db.get_relationship_by_inbound_upa("alice.onion/bobslotkey") is None
    assert db.conn.execute(
        "SELECT COUNT(*) AS n FROM relationship_prekeys"
    ).fetchone()["n"] == 0


def test_rename_host_contacts_migration(db, user_id):
    host_id = db.add_contact(user_id, "Host Node", "host.onion/h", is_host=True)
    friend_id = db.add_contact(user_id, "Host Node", "friend.onion/f")  # not is_host

    renamed = db.rename_host_contacts("Administrator", old_name="Host Node")
    assert renamed == 1  # only the host contact, not the same-named tenant contact
    assert db.get_contact(user_id, host_id)["name"] == "Administrator"
    assert db.get_contact(user_id, friend_id)["name"] == "Host Node"

    # Idempotent: a second run touches nothing
    assert db.rename_host_contacts("Administrator", old_name="Host Node") == 0


def test_duplicate_contact_upa_rejected(db, user_id):
    db.add_contact(user_id, "Ada", "other.onion/adaaddr")
    with pytest.raises(Exception):
        db.add_contact(user_id, "Ada again", "other.onion/adaaddr")


def test_message_transit_then_archive(db, user_id):
    contact_id = db.add_contact(user_id, "Host", "host.onion/h", is_host=True)
    envelope = {"header": {"n": 0}, "ciphertext": "b64"}
    msg_id = db.add_message(user_id, contact_id, "in", envelope=envelope)

    msg = db.get_message(user_id, msg_id)
    assert msg["read"] == 0
    assert msg["archive"] is None
    assert "ciphertext" in msg["envelope"]

    db.archive_message(msg_id, {"iv": "x", "ct": "y"})
    archived = db.get_message(user_id, msg_id)
    assert archived["envelope"] is None  # transit envelope destroyed
    assert archived["read"] == 1
    assert "ct" in archived["archive"]

    assert len(db.list_messages(user_id, contact_id)) == 1


def test_host_prekeys_single_use(db):
    prekey_id = db.add_host_prekey({"spk": "pub"}, {"spk_priv": "priv"})
    keys = db.take_host_prekey(prekey_id)
    assert keys == {"spk_priv": "priv"}
    assert db.take_host_prekey(prekey_id) is None  # one-time use
    assert db.take_host_prekey(12345) is None


def test_host_session_state(db, user_id):
    assert db.get_host_session(user_id) is None
    db.put_host_session(user_id, {"n_send": 1})
    db.put_host_session(user_id, {"n_send": 2})
    assert db.get_host_session(user_id) == {"n_send": 2}


def test_auth_sessions(db, user_id):
    token = db.create_auth_session(user_id)
    assert db.get_auth_session(token)["user_id"] == user_id
    db.delete_auth_session(token)
    assert db.get_auth_session(token) is None


def test_auth_session_expiry(db, user_id):
    token = db.create_auth_session(user_id, ttl_seconds=-1)
    assert db.get_auth_session(token) is None


def test_persistence_across_connections(tmp_path):
    path = tmp_path / "node.db"
    db1 = Database(path)
    uid = db1.create_user("user-x", "h.onion/x", b"\x03" * 32)
    db1.close()

    db2 = Database(path)
    assert db2.get_user(uid)["handle"] == "user-x"
    db2.close()


def test_guest_invite_lifecycle(db, user_id):
    inv_id = db.create_guest_invite(user_id, "Charlie", "alice.onion/charlieslot")
    assert db.get_guest_invite_by_upa("alice.onion/charlieslot")["id"] == inv_id
    assert db.get_guest_invite_by_upa("nope.onion/x") is None
    listed = db.list_guest_invites(user_id)
    assert len(listed) == 1
    assert listed[0]["claimed_user_id"] is None

    charlie_id = db.create_user(
        "user-charlie", "alice.onion/charlieslot", b"\x02" * 32, guest=True
    )
    db.claim_guest_invite(inv_id, charlie_id)
    claimed = db.get_guest_invite_by_upa("alice.onion/charlieslot")
    assert claimed["claimed_user_id"] == charlie_id
    assert db.get_user(charlie_id)["guest"] == 1


def test_device_link_lifecycle(db, user_id):
    db.create_device_link("link-abc", user_id, ttl_seconds=300)
    link = db.get_device_link("link-abc")
    assert link["user_id"] == user_id
    assert link["parcel"] is None
    assert link["consumed_user_id"] is None

    db.set_device_link_parcel("link-abc", "opaque-ciphertext")
    assert db.get_device_link("link-abc")["parcel"] == "opaque-ciphertext"

    other_user = db.create_user("user-other", "host.onion/other", b"\x03" * 32)
    db.consume_device_link("link-abc", other_user)
    assert db.get_device_link("link-abc")["consumed_user_id"] == other_user


def test_device_link_expiry(db, user_id):
    db.create_device_link("link-old", user_id, ttl_seconds=-1)  # already expired
    assert db.get_device_link("link-old") is None
