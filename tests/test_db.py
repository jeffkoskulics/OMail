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
