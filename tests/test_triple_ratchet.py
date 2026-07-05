import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from omail.crypto.kem import ML_KEM_768_NAME, X25519_KEM_NAME
from omail.crypto.triple_ratchet import (
    PrekeyBundle,
    TripleRatchet,
    make_prekey_bundle,
)


def _identity_seed():
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture(params=[ML_KEM_768_NAME, X25519_KEM_NAME])
def session(request):
    """An established Alice (initiator) / Bob (responder) session pair."""
    alice_seed, bob_seed = _identity_seed(), _identity_seed()
    bundle, bob_keys = make_prekey_bundle(bob_seed, kem_alg=request.param)
    # Bundles survive a JSON round trip (they are served over HTTP)
    bundle = PrekeyBundle.from_dict(json.loads(json.dumps(bundle.to_dict())))
    alice = TripleRatchet.initiate(alice_seed, bundle)
    first = alice.encrypt(b"hello bob")
    bob = TripleRatchet.respond(bob_keys, first["init"])
    assert bob.decrypt(first) == b"hello bob"
    return alice, bob


def test_handshake_blob_only_on_first_message(session):
    alice, _ = session
    assert "init" not in alice.encrypt(b"second")


def test_bidirectional_conversation(session):
    alice, bob = session
    for i in range(3):
        env = alice.encrypt(f"a->b {i}".encode())
        assert bob.decrypt(env) == f"a->b {i}".encode()
        env = bob.encrypt(f"b->a {i}".encode())
        assert alice.decrypt(env) == f"b->a {i}".encode()


def test_epoch_ratcheting_rotates_keys(session):
    alice, bob = session
    first_header = alice.encrypt(b"epoch1")["header"]
    # Same epoch: same ratchet keys
    assert alice.encrypt(b"epoch1b")["header"]["dh"] == first_header["dh"]
    # Bob replies, Alice receives -> Alice's next send starts a new epoch
    alice.decrypt(bob.encrypt(b"turn"))
    next_header = alice.encrypt(b"epoch2")["header"]
    assert next_header["dh"] != first_header["dh"]
    assert next_header["kem_pub"] != first_header["kem_pub"]
    assert next_header["kem_ct"] != first_header["kem_ct"]


def test_out_of_order_within_chain(session):
    alice, bob = session
    e0 = alice.encrypt(b"m0")
    e1 = alice.encrypt(b"m1")
    e2 = alice.encrypt(b"m2")
    assert bob.decrypt(e2) == b"m2"
    assert bob.decrypt(e0) == b"m0"
    assert bob.decrypt(e1) == b"m1"


def test_out_of_order_across_epochs(session):
    alice, bob = session
    late = alice.encrypt(b"late")          # epoch N, n=0
    alice.decrypt(bob.encrypt(b"reply"))   # forces Alice into epoch N+1
    fresh = alice.encrypt(b"fresh")
    assert bob.decrypt(fresh) == b"fresh"  # bob banks the skipped epoch-N key
    assert bob.decrypt(late) == b"late"


def test_tampered_header_fails(session):
    alice, bob = session
    env = alice.encrypt(b"payload")
    env["header"]["n"] += 7
    with pytest.raises(Exception):
        bob.decrypt(env)


def test_tampered_ciphertext_fails(session):
    alice, bob = session
    env = alice.encrypt(b"payload")
    raw = bytearray(__import__("base64").b64decode(env["ciphertext"]))
    raw[0] ^= 0xFF
    env["ciphertext"] = __import__("base64").b64encode(bytes(raw)).decode()
    with pytest.raises(Exception):
        bob.decrypt(env)


def test_replay_rejected(session):
    alice, bob = session
    env = alice.encrypt(b"once")
    assert bob.decrypt(env) == b"once"
    with pytest.raises(Exception):
        bob.decrypt(env)


def test_state_serialization_roundtrip(session):
    alice, bob = session
    env = alice.encrypt(b"before hibernation")
    # Both parties persist and reload state (vault / database round trip)
    bob2 = TripleRatchet.from_dict(json.loads(json.dumps(bob.to_dict())))
    assert bob2.decrypt(env) == b"before hibernation"
    alice2 = TripleRatchet.from_dict(json.loads(json.dumps(alice.to_dict())))
    reply = bob2.encrypt(b"still here")
    assert alice2.decrypt(reply) == b"still here"


def test_serialization_preserves_skipped_keys(session):
    alice, bob = session
    e0 = alice.encrypt(b"m0")
    e1 = alice.encrypt(b"m1")
    assert bob.decrypt(e1) == b"m1"  # m0's key is banked
    bob2 = TripleRatchet.from_dict(json.loads(json.dumps(bob.to_dict())))
    assert bob2.decrypt(e0) == b"m0"


def test_forward_secrecy_across_epochs(session):
    """Compromising current state must not reveal prior epochs' messages."""
    alice, bob = session
    old_env = alice.encrypt(b"old secret")
    assert bob.decrypt(old_env) == b"old secret"
    # Advance one full round trip so both sides rotate epochs
    alice.decrypt(bob.encrypt(b"turn"))
    bob.decrypt(alice.encrypt(b"turn back"))
    with pytest.raises(Exception):
        bob.decrypt(old_env)  # old message keys are gone


def test_prekey_bundle_signature_verified():
    bundle, _ = make_prekey_bundle(_identity_seed())
    bundle.spk_sig = bytes(64)
    with pytest.raises(Exception):
        TripleRatchet.initiate(_identity_seed(), bundle)


def test_kem_alg_mismatch_rejected():
    alice_seed, bob_seed = _identity_seed(), _identity_seed()
    bundle, bob_keys = make_prekey_bundle(bob_seed, kem_alg=X25519_KEM_NAME)
    alice = TripleRatchet.initiate(alice_seed, bundle)
    first = alice.encrypt(b"hi")
    bob_keys.kem_alg = ML_KEM_768_NAME
    with pytest.raises(ValueError, match="KEM algorithm mismatch"):
        TripleRatchet.respond(bob_keys, first["init"])


def test_too_many_skipped_rejected(session):
    alice, bob = session
    for _ in range(3):
        alice.encrypt(b"dropped")
    env = alice.encrypt(b"arrives")
    env["header"]["n"] = 10_000
    with pytest.raises(ValueError, match="Too many skipped"):
        bob.decrypt(env)
