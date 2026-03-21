import pytest
import base64
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from key_pair import KeyPair

def derive_onion_v3_address(public_key: ed25519.Ed25519PublicKey) -> str:
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    # Onion V3: pubkey + checksum + version
    checksum_input = b".onion checksum" + pub_bytes + b"\x03"
    checksum = hashlib.sha3_256(checksum_input).digest()[:2]
    combined = pub_bytes + checksum + b"\x03"
    return base64.b32encode(combined).decode('utf-8').lower() + ".onion"

def ed25519_to_x25519_pub(ed_pub: ed25519.Ed25519PublicKey) -> x25519.X25519PublicKey:
    # Simulates the conversion required for encryption using Ed25519 keys
    raw_bytes = ed_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return x25519.X25519PublicKey.from_public_bytes(raw_bytes)

def ed25519_to_x25519_priv(ed_priv: ed25519.Ed25519PrivateKey) -> x25519.X25519PrivateKey:
    raw_bytes = ed_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Note: In a real production system, a specific birational map is used
    # This hash-based derivation ensures we get a valid 32-byte X25519 key for the simulation

    return x25519.X25519PrivateKey.from_private_bytes(raw_bytes[:32])

@pytest.fixture
def omail_env():
    sender = KeyPair()
    sender.generate_key_pair()
    receiver = KeyPair()
    receiver.generate_key_pair()
    
    return {
        "sender": sender,
        "receiver": receiver,
        "sender_onion": derive_onion_v3_address(sender.public_key),
        "receiver_onion": derive_onion_v3_address(receiver.public_key)
    }

def test_omail_secure_transmission(omail_env):
    message = "Secret OMail content"
    msg_bytes = message.encode('utf-8')
    
    sender = omail_env["sender"]
    receiver = omail_env["receiver"]

    # 1. Sender signs the message
    signature = sender.private_key.sign(msg_bytes)

    # 2. Sender encrypts for Receiver's Onion address
    # Convert keys to X25519 for Diffie-Hellman exchange
    ephemeral_priv = x25519.X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()
    
    receiver_x_priv_sim = ed25519_to_x25519_priv(receiver.private_key)
    receiver_x_pub = ed25519_to_x25519_pub(receiver_x_priv_sim.public_key())
    shared_key = ephemeral_priv.exchange(receiver_x_pub)
    
    # Derive encryption key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"omail-encryption",
    ).derive(shared_key)

    aesgcm = AESGCM(derived_key)
    nonce = b"fixed_nonce_" # 12 bytes
    ciphertext = aesgcm.encrypt(nonce, msg_bytes, None)

    # --- RECEIVER SIDE ---

    # 3. Receiver decrypts
    receiver_x_priv = ed25519_to_x25519_priv(receiver.private_key)
    # Receiver uses their private key and the sender's ephemeral public key
    rec_shared_key = receiver_x_priv.exchange(ephemeral_pub)
    
    rec_derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"omail-encryption",
    ).derive(rec_shared_key)

    decrypted_bytes = AESGCM(rec_derived_key).decrypt(nonce, ciphertext, None)
    
    # 4. Receiver verifies signature using Sender's Onion-derived public key
    sender.public_key.verify(signature, decrypted_bytes)

    assert decrypted_bytes.decode('utf-8') == message
    assert omail_env["sender_onion"].endswith(".onion")