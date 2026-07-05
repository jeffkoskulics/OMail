import json

import pytest

from omail.webauthn import PasskeyManager, new_handle
from tests.soft_authenticator import SoftAuthenticator

RP_ID = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"
ORIGIN = f"http://{RP_ID}"


@pytest.fixture
def manager():
    return PasskeyManager(RP_ID, "Test Host OMail")


@pytest.fixture
def authenticator():
    return SoftAuthenticator(RP_ID, ORIGIN)


def test_new_handle_is_opaque():
    h1, h2 = new_handle(), new_handle()
    assert h1 != h2
    assert h1.startswith("user-")
    assert len(h1) == len("user-") + 12


def test_registration_options_shape(manager):
    options, state = manager.begin_registration("user-abc", b"\x01\x02")
    pk = options["publicKey"]
    assert pk["rp"]["id"] == RP_ID
    assert pk["rp"]["name"] == "Test Host OMail"
    assert pk["authenticatorSelection"]["residentKey"] == "required"
    assert pk["extensions"]["prf"] == {}
    assert "challenge" in state
    # Options must survive JSON serialization for the wire
    json.dumps(options, default=str)


def test_full_registration_and_login(manager, authenticator):
    handle = new_handle()
    options, state = manager.begin_registration(handle, b"user-id-bytes")
    response = authenticator.create(json.loads(json.dumps(options, default=str)))
    cred_id, cred_blob, sign_count = manager.complete_registration(state, response)
    assert cred_id == authenticator.credential_id
    assert isinstance(cred_blob, bytes) and len(cred_blob) > 50

    # Usernameless login with the stored credential blob
    auth_options, auth_state = manager.begin_authentication()
    assert auth_options["publicKey"]["rpId"] == RP_ID
    assertion = authenticator.get(json.loads(json.dumps(auth_options, default=str)))
    matched = manager.complete_authentication(auth_state, assertion, [cred_blob])
    assert matched == authenticator.credential_id


def test_registration_rejects_wrong_origin(manager):
    evil = SoftAuthenticator(RP_ID, "http://evil.example.com")
    options, state = manager.begin_registration("user-x", b"\x01")
    response = evil.create(json.loads(json.dumps(options, default=str)))
    with pytest.raises(Exception):
        manager.complete_registration(state, response)


def test_registration_rejects_wrong_challenge(manager, authenticator):
    options, state = manager.begin_registration("user-x", b"\x01")
    other_options, _ = manager.begin_registration("user-x", b"\x01")
    response = authenticator.create(
        json.loads(json.dumps(other_options, default=str))
    )
    with pytest.raises(Exception):
        manager.complete_registration(state, response)


def test_authentication_rejects_unknown_credential(manager, authenticator):
    options, state = manager.begin_registration("user-x", b"\x01")
    response = authenticator.create(json.loads(json.dumps(options, default=str)))
    _, cred_blob, _ = manager.complete_registration(state, response)

    stranger = SoftAuthenticator(RP_ID, ORIGIN)
    stranger.user_handle = b"\x01"
    auth_options, auth_state = manager.begin_authentication()
    assertion = stranger.get(json.loads(json.dumps(auth_options, default=str)))
    with pytest.raises(Exception):
        manager.complete_authentication(auth_state, assertion, [cred_blob])


def test_extra_origins_accepted():
    manager = PasskeyManager(RP_ID, "Test", extra_origins={"http://gateway.local"})
    gateway_auth = SoftAuthenticator(RP_ID, "http://gateway.local")
    options, state = manager.begin_registration("user-x", b"\x01")
    response = gateway_auth.create(json.loads(json.dumps(options, default=str)))
    cred_id, _, _ = manager.complete_registration(state, response)
    assert cred_id == gateway_auth.credential_id
