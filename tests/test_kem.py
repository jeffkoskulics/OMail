import pytest

from omail.crypto.kem import (
    ML_KEM_768_NAME,
    X25519_KEM_NAME,
    MLKEM768,
    X25519KEM,
    get_kem,
)


@pytest.mark.parametrize("kem", [MLKEM768, X25519KEM])
def test_encaps_decaps_roundtrip(kem):
    pub, priv = kem.generate_keypair()
    ct, ss_sender = kem.encaps(pub)
    ss_receiver = kem.decaps(priv, ct)
    assert ss_sender == ss_receiver
    assert len(ss_sender) == 32


@pytest.mark.parametrize("kem", [MLKEM768, X25519KEM])
def test_distinct_encapsulations(kem):
    pub, _ = kem.generate_keypair()
    ct1, ss1 = kem.encaps(pub)
    ct2, ss2 = kem.encaps(pub)
    assert ct1 != ct2
    assert ss1 != ss2


def test_x25519_kem_wrong_key_yields_different_secret():
    pub, _ = X25519KEM.generate_keypair()
    _, wrong_priv = X25519KEM.generate_keypair()
    ct, ss = X25519KEM.encaps(pub)
    assert X25519KEM.decaps(wrong_priv, ct) != ss


def test_get_kem_lookup():
    assert get_kem(ML_KEM_768_NAME) is MLKEM768
    assert get_kem(X25519_KEM_NAME) is X25519KEM
    with pytest.raises(ValueError, match="Unknown KEM"):
        get_kem("ROT13")
