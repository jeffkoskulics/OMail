import pytest
from your_module import KeyPair  # Replace with your actual filename

def test_key_generation():
    ok = KeyPair()
    ok.generate_key_pair()
    assert ok.private_key is not None
    assert ok.public_key is not None
    assert "BEGIN PRIVATE KEY" in ok.get_private_str()
    assert "BEGIN PUBLIC KEY" in ok.get_public_str()

def test_serialization_roundtrip():
    ok1 = KeyPair()
    ok1.generate_key_pair()
    data = ok1.serialize()

    ok2 = KeyPair()
    ok2.deserialize(data)
    
    # Check if the serialized strings match
    assert ok1.get_private_str() == ok2.get_private_str()
    assert ok1.get_public_str() == ok2.get_public_str()

def test_mismatched_key_validation():
    ok1 = KeyPair()
    ok1.generate_key_pair()
    
    ok2 = KeyPair()
    ok2.generate_key_pair()
    
    # Create a mismatched payload
    bad_data = {
        "private": ok1.get_private_str(),
        "public": ok2.get_public_str()  # Key from a different pair
    }
    
    with pytest.raises(ValueError, match="Key-pair mismatch"):
        ok1.deserialize(bad_data)
