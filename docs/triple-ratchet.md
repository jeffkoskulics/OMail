# The Triple Ratchet Protocol

OMail's encryption combines Signal's Double Ratchet with a third **KEM ratchet** that mixes a post-quantum shared secret (ML-KEM-768) into every epoch. The result is forward secrecy and post-compromise security against both classical *and* quantum adversaries.

## Three Ratcheting Mechanisms

### 1. DH Ratchet (X25519)

Every epoch, a fresh Diffie-Hellman exchange generates new root and chain keys:

```python
DH_new = X25519(my_ephemeral_private, their_ephemeral_public)
root_key_new = HKDF(root_key_old, DH_new, salt="dh")
```

This provides **forward secrecy**: compromising a past message key doesn't compromise future messages, because the DH ratchet has moved on.

### 2. KEM Ratchet (ML-KEM-768)

Every epoch, a fresh ML-KEM ciphertext encapsulates a shared secret and mixes it into the root key:

```python
kem_ct, kem_ss = ML_KEM_768.encaps(their_kem_public_key)
root_key_new = HKDF(root_key_new, kem_ss, salt="kem")
```

ML-KEM-768 is FIPS 203 approved and resists classical factoring attacks. By mixing it into every epoch, OMail's encryption is **post-quantum secure** from day one — even if quantum computers emerge, past sessions remain secret.

A classical X25519-KEM mode exists for constrained peers; the algorithm is negotiated at session start.

### 3. Symmetric-Key Ratchet (HMAC-SHA256 chains)

For each message, a symmetric chain derives one-time AES-256-GCM keys:

```python
chain_key_new = HMAC_SHA256(chain_key, 0x01)
msg_key = HMAC_SHA256(chain_key, 0x02)
ciphertext = AES_256_GCM(msg_key, plaintext, associated_data=header)
```

Each message gets a unique key. Headers are authenticated as associated data, so tampering is detected.

## PQXDH Handshake

Sessions begin with a hybrid handshake against a signed prekey bundle:

```
1. X25519(my_ephemeral,      their_ephemeral)        → classical DH
2. X25519(my_ephemeral,      their_signed_prekey)    → deniability
3. X25519(my_identity,       their_signed_prekey)    → long-term binding
4. ML_KEM_768.encaps(their_kem_pubkey)               → post-quantum
        ↓
All mixed through HKDF → root_key, chain_key
```

This is inspired by PQXDH (Post-Quantum X3DH, Signal's protocol for hybrid crypto).

Benefits:
- **Forward secrecy**: Ephemeral keys ensure sessions aren't compromised by static key theft
- **Deniability**: Either party could have created the first message
- **Post-quantum security**: ML-KEM binds the session from the start
- **Identity verification**: Long-term keys can be verified out-of-band

## Out-of-Order Delivery

Messages may arrive out of order (especially over Tor). Skipped message keys are banked:

```python
if msg_num > next_msg_num:
    # Message N arrived; we're expecting M < N
    for skipped in range(next_msg_num, msg_num):
        bank[skipped] = HMAC_SHA256(chain_key, 0x02)
        chain_key = HMAC_SHA256(chain_key, 0x01)
    # Now decrypt message N normally
```

This allows out-of-order delivery while preventing replay attacks. Old banked keys are rotated out periodically.

## State Serialization

Ratchet state (root key, chain keys, KEM state) serializes to JSON for storage in the encrypted vault:

```json
{
  "root_key": "base64...",
  "chain_key_send": "base64...",
  "chain_key_recv": "base64...",
  "dh_send": {
    "private": "base64...",
    "public": "base64..."
  },
  "dh_recv_public": "base64...",
  "kem_alg": "ML-KEM-768",
  "kem_send_keypair": {
    "public": "base64...",
    "private": "base64..."
  },
  "kem_recv_pubkey": "base64...",
  "skipped_keys": {
    "epoch_123": {
      "msg_5": "base64..."
    }
  }
}
```

This allows sessions to survive device restarts, app crashes, and client migrations.

## Wire Format Compatibility

The Triple Ratchet is implemented twice:

- **Python** (`omail/crypto/triple_ratchet.py`) — used by the host and in tests
- **JavaScript** (`src/omail/static/crypto.js`) — used by the browser client

Both implementations produce **byte-identical** ciphertexts. This is verified by interop tests where:
1. Python publishes a prekey bundle
2. JavaScript initiates and sends messages
3. Python decrypts them correctly
4. Python replies; JavaScript decrypts correctly

The same wire format means any OMail client (Python, JS, future Rust/Go implementations) can talk to any other.

## Implementation Details

See `omail/crypto/triple_ratchet.py` for the full implementation:

```python
from omail.crypto.triple_ratchet import (
    TripleRatchet,           # Main protocol class
    ResponderKeys,           # Server-side prekey bundle
    make_prekey_bundle,      # Generate signed bundle
)

# Initiate a session
alice = TripleRatchet.initiate(my_seed, bob_bundle)
envelope = await alice.encrypt(message_bytes)

# Respond to a handshake
bob = TripleRatchet.respond(bob_keys, alice_init_envelope)
plaintext = await bob.decrypt(alice_message)
```

## Security Properties

✓ **Forward secrecy**: Compromising a message key doesn't compromise others  
✓ **Post-compromise security**: Ratcheting forward recovers security after key theft  
✓ **Post-quantum security**: ML-KEM-768 resists quantum adversaries  
✓ **Replay protection**: Sequence numbers and banked keys  
✓ **Tampering detection**: GCM authentication on every message  
✓ **Deniability**: Ephemeral-key handshake  
✓ **Out-of-order delivery**: Banked skipped-key recovery  

## Contrast with Email

Email (SMTP) sends plaintext over TLS. If TLS is compromised:
- All past messages are decrypted (no forward secrecy)
- All future messages are decrypted (no post-compromise recovery)
- Quantum computers break the TLS handshake retroactively

OMail's Triple Ratchet means:
- Past messages remain secret (old DH epochs aren't recomputable)
- Future messages are secure (forward ratcheting)
- Quantum computers can't break past sessions (KEM binds security to each epoch)
