import pytest
import base64
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import nacl.bindings as b
from key_pair import KeyPair

def ed25519_to_x25519_pub(ed_pub: ed25519.Ed25519PublicKey) -> x25519.X25519PublicKey:
    """Converts an Ed25519 Public Key to an X25519 Public Key using birational mapping."""
    raw_bytes = ed_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    # Returns raw bytes from libsodium
    x25519_bytes = b.crypto_sign_ed25519_pk_to_curve25519(raw_bytes)
    # Wrap in cryptography object for compatibility
    return x25519.X25519PublicKey.from_public_bytes(x25519_bytes)

def ed25519_to_x25519_priv(ed_priv: ed25519.Ed25519PrivateKey) -> x25519.X25519PrivateKey:
    # 1. Get the 32-byte seed
    seed = ed_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    # 2. Get the 32-byte public key
    pub_bytes = ed_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    # 3. Concatenate to form the 64-byte secret key required by libsodium
    sk_64 = seed + pub_bytes
    
    # 4. Convert to X25519 private scalar
    x25519_priv_bytes = b.crypto_sign_ed25519_sk_to_curve25519(sk_64)
    
    return x25519.X25519PrivateKey.from_private_bytes(x25519_priv_bytes)

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

    # --- SENDER SIDE ---
    # 1. Sender signs the message with their Ed25519 key
    signature = sender.private_key.sign(msg_bytes)

    # 2. Sender encrypts for Receiver's Onion address
    # Generate an ephemeral key for this specific message
    ephemeral_priv = x25519.X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()
    
    # SENDER ONLY USES RECEIVER'S PUBLIC KEY
    receiver_x_pub = ed25519_to_x25519_pub(receiver.public_key)
    shared_key = ephemeral_priv.exchange(receiver_x_pub)
    
    # Derive encryption key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"omail-encryption",
    ).derive(shared_key)

    aesgcm = AESGCM(derived_key)
    nonce = b"fixed_nonce_" # In production, use a random 12-byte nonce
    ciphertext = aesgcm.encrypt(nonce, msg_bytes, None)

    # --- RECEIVER SIDE ---
    # 3. Receiver decrypts using their Ed25519-derived X25519 Private Key
    receiver_x_priv = ed25519_to_x25519_priv(receiver.private_key)
    
    # Receiver uses their private key and the sender's ephemeral public key
    rec_shared_key = receiver_x_priv.exchange(ephemeral_pub)
    
    rec_derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"omail-encryption",
    ).derive(rec_shared_key)

    # This will now succeed because both shared keys match
    decrypted_bytes = AESGCM(rec_derived_key).decrypt(nonce, ciphertext, None)
    
    # 4. Receiver verifies the signature using Sender's Public Key
    sender.public_key.verify(signature, decrypted_bytes)
    
    assert decrypted_bytes.decode('utf-8') == message