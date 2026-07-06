# Message Flow and Routing

> **Terminology and target model:** see [concepts.md](concepts.md) for the
> canonical definitions (Host, Administrator, Tenant, Guest) and the
> per-relationship UPA model with its two-step connect handshake. This page
> details the message-passing and routing mechanics; where it shows a
> single host carrying both correspondents, the same envelope path applies
> across hosts once federation transport (Phase 2) carries it over Tor.

## Overview

```
Alice (Tor Browser)           Bob (Tor Browser)
      │                              │
      │ passkey registration         │
      ├─ WebAuthn PRF ceremony       │
      │  (vault key derived)         │
      │                              │
      ├─ POST /api/prekeys           │
      │  (publishes her bundle)      │
      │                              │
      ├─ GET /api/prekeys/bob_upa    │ GET /api/prekeys/alice_upa
      │  (fetches Bob's bundle)      │ (fetches Alice's bundle)
      │                              │
      ├─ JS Triple Ratchet.initiate  │
      │  (handshake)                 │
      │                              │
      ├─ POST /api/messages          │
      │  (encrypted envelope) ──────►│ Tor routing (blind)
      │                              │
      │  WebSocket notify ◄──────────┤ GET /api/messages
      │  (new message available)     │ (polls or WebSocket)
      │                              │
      │                              ├─ JS Triple Ratchet.decrypt
      │                              │  (decrypts in browser)
      │                              │
      │                              ├─ POST /api/messages/{id}/archive
      │  Plaintext envelope deleted  │ (uploads vault_blob, message archived)
      │  by server ◄─────────────────┤
      │                              │
      │◄─────── reply envelope ──────┤ POST /api/messages
      │                              │ (sends reply)
      │                              │
      └─ JS Triple Ratchet.decrypt   │
         (decrypts reply)             │
```

## Step-by-Step

### 1. Registration and Prekey Publication

Both users register independently:

```
POST /api/webauthn/register/begin
  → { challenge, user_id, rp_id, attestation, extensions: {prf} }

User taps passkey
  ↓
Authenticator evaluates PRF → 32-byte vault_key (stays in authenticator)
  ↓
POST /api/webauthn/register/complete
  ← { attestation_object, client_data_json, prf_output? }
  → 201 Created { credential_id, user_handle }

User is assigned a UPA: host.onion/user-key-hash

Publish prekey bundle:
POST /api/prekeys
  ← { identity_key: Ed25519-pub, signed_prekey: X25519-pub, kem_public_key: ML-KEM-pub, ... }
  → 201 Created
```

### 2. Alice Initiates a Session

Alice fetches Bob's prekey bundle:

```
GET /api/prekeys/bob_upa
  → { bundle: {identity_key, signed_prekey, kem_public_key, ...} }
```

Alice's browser runs Triple Ratchet.initiate:

```javascript
const alice = await TripleRatchet.initiate(
  seed,  // random 32 bytes
  bob_bundle  // his prekeys
);
// Handshake happens inside JS:
// 1. X25519 ephemeral-to-ephemeral
// 2. X25519 ephemeral-to-signed-prekey
// 3. X25519 identity-to-signed-prekey
// 4. ML-KEM-768 encapsulation to his KEM key
// All mixed through HKDF → root_key, chain_key
```

Alice's ratchet state is serialized and saved to her encrypted vault:

```javascript
alice_state = alice.toDict();  // JSON-serializable
POST /api/vault
  ← { vault_blob: AES_256_GCM(vault_key, {alice_state, ...}) }
```

### 3. Alice Sends Message 1

Alice encrypts and sends:

```javascript
const envelope = await alice.encrypt(
  new TextEncoder().encode("Hello Bob!")
);
// Returns: {
//   "init": {handshake_data...},  // only on first message
//   "header": {...},               // DH + KEM state
//   "ciphertext": "base64..."      // AES-256-GCM encrypted
// }

POST /api/messages
  ← { target_upa: bob_upa, envelope: {...} }
  → { id: "msg-123" }
```

The server:
1. Looks up Bob's user_id by UPA
2. Stores the opaque envelope in the `messages` table
3. Pushes notification to Bob's WebSocket (if connected)

Alice's envelope is:
- Encrypted end-to-end (server sees only ciphertext)
- Contains her ratchet state in the header
- Timestamped but not tied to identity (blind routing)

### 4. Bob Receives the Message

Bob's browser is listening on WebSocket:

```javascript
ws = new WebSocket('wss://host.onion/socket');
ws.on('message', async (ev) => {
  if (ev.type === 'notify') {
    const messages = await fetch('/api/messages');
    // ... fetch and decrypt
  }
});
```

Bob fetches pending messages:

```
GET /api/messages
  → [{ id: "msg-123", envelope: {...} }]
```

Bob's browser decrypts:

```javascript
const bob_ratchet = TripleRatchet.respond(
  bob_keys,  // his pre-generated keys
  envelope.init  // Alice's handshake
);

const plaintext = await bob_ratchet.decrypt(envelope);
// Returns: "Hello Bob!"
```

Bob's ratchet state is now shared with Alice's — they're synchronized on the same session.

### 5. Bob Archives the Message

Bob clicks "Archive" in the UI:

```javascript
const archive_blob = await vault_encrypt(
  vault_key,
  { message_id, sender_upa, timestamp, plaintext: "Hello Bob!" }
);

POST /api/messages/msg-123/archive
  ← { vault_blob: "AES-256-GCM ciphertext" }
  → 200 OK

DELETE /api/messages/msg-123
  ← (no body)
  → 204 No Content
```

The server:
1. Moves the message to the `archive` table (still encrypted)
2. Deletes the plaintext-bearing envelope from `messages`
3. The archive is opaque — the server doesn't know the message content

### 6. Bob Sends a Reply

Bob's browser creates a new envelope:

```javascript
const reply_envelope = await bob_ratchet.encrypt(
  new TextEncoder().encode("Hi Alice!")
);

POST /api/messages
  ← { target_upa: alice_upa, envelope: {...} }
  → { id: "msg-124" }
```

Alice's browser is notified, fetches, and decrypts:

```javascript
const reply_plaintext = await alice_ratchet.decrypt(reply_envelope);
// Returns: "Hi Alice!"
```

Now both have sent a message and ratcheted forward (DH + KEM epochs changed).

## Routing Modes

The server implements three routing modes:

### Mode 1: Host-to-Self (Deterministic Response)

Target UPA is the host's own UPA:

```python
if target_upa == host.own_upa:
    response = host.receive_envelope(envelope)
    return response
```

The server decrypts the envelope (it has the key), verifies it's a valid handshake, responds with a deterministic reply (e.g., "pong" if message is "ping"), and sends the reply envelope back.

Used for testing, host node status checks.

### Mode 2: Local Blind Delivery

Target UPA belongs to a user on this host:

```python
recipient_user = db.users.find_by_upa(target_upa)
if recipient_user:
    db.messages.insert(recipient_id=recipient_user.id, envelope=envelope)
    ws.push_notify(recipient_user.id)
    return 200
```

The server:
1. Looks up the recipient by UPA
2. Stores the opaque envelope
3. Notifies the recipient (if connected via WebSocket)
4. Returns 200 OK

The server never opens the envelope; routing is blind.

### Mode 3: Remote Federation (Queued)

Target UPA's host is remote:

```python
remote_host_onion = target_upa.split('.onion')[0] + '.onion'
if remote_host_onion != host.own_onion:
    db.queued_messages.insert(
        remote_host=remote_host_onion,
        target_upa=target_upa,
        envelope=envelope
    )
    return 200
```

The message is queued for delivery to the remote host (federation is TBD).

## Metadata Isolation

Even though routing is "blind", OMail still minimizes metadata:

| What server sees | Why it matters |
|------------------|----------------|
| Message size | Can be padded to fixed size (TBD) |
| Timestamp | Only when sent (arrival time private to recipient) |
| Sender's onion | Only if sender reveals it (can be routed through intermediaries) |
| Recipient's onion | Only if sender sends to that host (blind routing hides this) |

Full metadata anonymity requires:
- Onion routing (Tor) ✓
- Blind envelope encryption ✓
- Recipient-side timing (no server-side logs) ✓
- No typing indicators or read receipts ✓

## Session State Persistence

After each message, ratchet state is serialized to JSON and encrypted:

```javascript
state = alice_ratchet.toDict();
await vault_encrypt(vault_key, state);
await fetch('POST /api/vault', {vault_blob: ciphertext});
```

This allows:
- Device restarts (state recovered from vault)
- Browser tab refreshes (state reloaded from vault)
- Client migrations (export vault, import on new device)
- Concurrent sessions (state file locked during writes)

## Out-of-Order Delivery

Messages may arrive out of order over Tor:

```
Alice sends: msg-1, msg-2, msg-3
Bob receives: msg-2, msg-1, msg-3
```

Triple Ratchet handles this with **skipped-key banking**:

```python
if msg_num > next_msg_num:
    # Bank keys for messages we haven't received yet
    for skipped in range(next_msg_num, msg_num):
        banked[skipped] = derive_key()
    # Advance chain for the gap
    chain_key = advance_chain(chain_key)

# Now decrypt msg-2 (even though we're expecting msg-1)
plaintext = decrypt(msg_key=banked[2], ...)

# When msg-1 arrives later, look it up in banked keys
plaintext = decrypt(msg_key=banked[1], ...)
```

Very old banked keys are rotated out to prevent unbounded memory growth.

## Performance Characteristics

- **Handshake**: ~100ms (PQXDH + KEM encapsulation)
- **Encrypt**: ~10ms per message (chain advancement + AES-GCM)
- **Decrypt**: ~10ms per message (same)
- **State serialization**: ~1ms (JSON encoding of ratchet state)
- **Vault upload**: ~50ms (network-bound, depends on Tor latency)

Tor adds 1-3 second latency per hop (typical 3 hops through Tor).
