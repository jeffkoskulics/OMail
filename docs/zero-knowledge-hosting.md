# Zero-Knowledge Hosting

OMail is designed so the server can never read your messages or keys — even if completely compromised.

## What the Server Stores

The database contains exactly these tables:

| Table | Contents | Encrypted? | Server Readable? |
|-------|----------|-----------|-----------------|
| `users` | opaque handle, UPA, Ed25519 **public** key | No | N/A (public) |
| `credentials` | WebAuthn credential IDs + COSE public keys | No | No (public keys only) |
| `vaults` | AES-GCM ciphertext blobs | Yes | No |
| `messages` | Transit ratchet envelopes | Yes | No |
| `user_prekeys` | **Public** prekey bundles | No | No (public keys only) |

### The Critical Table: `vaults`

The vault stores:
- Ed25519 private key
- X25519 private keys (for DH ratchet)
- ML-KEM-768 private keys (for KEM ratchet)
- Triple Ratchet session state
- Contact list
- Message archive

All encrypted with AES-256-GCM:

```
vault_key = PRF_output  (32 bytes from authenticator)
vault_ciphertext = AES_256_GCM(vault_key, {ed25519_priv, x25519_privs, ratchet_state, ...})
```

The server stores the opaque ciphertext but never sees the plaintext.

## The WebAuthn PRF Extension

The vault key is derived **inside your authenticator** — it never reaches the server or even the browser:

```
Registration:
  Your device generates a credential (biometric/security key)
  Authenticator evaluates PRF(credential, salt) → 32-byte secret
  Secret stays in authenticator (server never sees it)

Authentication:
  You tap biometric/security key
  Authenticator evaluates PRF(credential, salt) → same 32-byte secret
  Returns secret to browser only after successful auth
  Browser uses it to decrypt vault_blob ← server
  Your keys come alive only on your device
```

Even if the server is hacked and every database table is stolen:
- `vault_blob` is useless without the PRF key
- `credentials` table contains only COSE public keys
- `vaults` table is opaque ciphertext
- The attacker has no way to derive the PRF output (it's evaluated inside your authenticator)

## Message Flow: Encryption at Rest

When you send a message to a contact:

```
1. Your browser fetches their prekey bundle (public keys)
2. Your browser runs Triple Ratchet.initiate(their_bundle)
3. Your browser encrypts: ciphertext = encrypt(message, ratchet_state)
4. Your browser sends ciphertext to server (envelope)
5. Server routes envelope to recipient (blind routing)
6. Recipient's browser downloads envelope
7. Recipient's browser runs Triple Ratchet.decrypt(envelope)
8. Recipient uploads vault_blob (archive) to server
9. Server deletes plaintext envelope
```

The server never sees the message. It only sees:
- An opaque ciphertext transit envelope
- Request to move it to archive
- Request to delete it

## Message Archive

When you receive a message and click "Archive", your browser:

```
1. Decrypts the ratchet envelope (in browser memory)
2. Reads the plaintext
3. Encrypts message + metadata with vault_key
4. Uploads vault_blob to server
5. Requests DELETE /api/messages/{id}
```

The message is encrypted for long-term storage. The plaintext-bearing envelope is destroyed immediately. The server never holds plaintext.

## Prekey Bundles: Public by Design

Your prekey bundle is published publicly so others can initiate sessions:

```json
{
  "identity_key": "base64 Ed25519 public key",
  "signed_prekey": "base64 X25519 public key",
  "signed_prekey_signature": "Ed25519 signature of above",
  "onetime_prekeys": [
    "base64 X25519 public key",
    ...
  ],
  "kem_public_key": "base64 ML-KEM-768 public key"
}
```

This contains **only public keys**. Your private halves stay in your encrypted vault. An attacker who gets your prekey bundle learns nothing about your message content — they can only initiate a session, which requires your approval (the handshake mixes in your identity key).

## Onboarding Collects No Personal Data

To create an account:

✗ **Not asked for:**
- Email address
- Password
- Name
- Phone number
- Date of birth
- Recovery email
- Recovery phone

✓ **Only required:**
- A passkey (your authenticator)
- Acceptance of the UPA as your identity

Your identity **is** your cryptographic key. There's nothing else to verify.

## Database Schema

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  handle TEXT UNIQUE,           -- opaque reference
  upa TEXT UNIQUE,              -- base32 UPA
  public_key BLOB,              -- Ed25519 public key (no private!)
  created_at TIMESTAMP
);

CREATE TABLE credentials (
  id INTEGER PRIMARY KEY,
  user_id INTEGER,
  credential_id BLOB UNIQUE,    -- WebAuthn credential ID
  cose_key BLOB,                -- COSE public key
  created_at TIMESTAMP
);

CREATE TABLE vaults (
  id INTEGER PRIMARY KEY,
  user_id INTEGER UNIQUE,
  vault_blob BLOB,              -- AES-256-GCM ciphertext (opaque!)
  updated_at TIMESTAMP
);

CREATE TABLE messages (
  id INTEGER PRIMARY KEY,
  recipient_id INTEGER,
  envelope BLOB,                -- Triple Ratchet envelope (encrypted!)
  received_at TIMESTAMP
);

CREATE TABLE user_prekeys (
  id INTEGER PRIMARY KEY,
  user_id INTEGER,
  bundle_json TEXT,             -- Public prekey bundle
  created_at TIMESTAMP
);
```

**Key principle:** Every table contains only data the server needs to route messages. Private key material appears nowhere.

## Threat Model

### Server is Compromised

Attacker gains full database access:

✓ Can read `users`, `credentials`, `user_prekeys` (all public)
✗ Cannot read `vaults` (opaque ciphertext, vault key in authenticator)
✗ Cannot decrypt `messages` (Triple Ratchet envelopes, keys in vault)
✗ Cannot forge UPAs (checksummed encoding)
✗ Cannot impersonate users (Ed25519 signatures)

### Backup Power Supply is Stolen

Attacker gains access to your device's stored vault_blob:

✗ Cannot decrypt it (vault_key is in your authenticator, not on disk)
✓ If they have your authenticator too, they can decrypt (hence: secure your authenticator)

### Authenticator is Compromised

Attacker can derive the PRF key from your authenticator:

✗ This defeats everything (they have the master key)
✓ Use a hardware security key (YubiKey, etc.) rather than device biometric for maximum security

### Tor is Monitored

Attacker monitors your onion connections:

✓ Cannot see message content (end-to-end encrypted)
✓ Cannot see recipient addresses (blind routing to `.onion` hidden service)
✗ Can see timing and volume (metadata), which is why OMail integrates Tor, not just HTTPS

## Migration to Self-Hosting

When you migrate to your own node:

```
1. Generate new Ed25519 key (your sovereign identity)
2. Publish Tor hidden service
3. Rewrite UPA routing: old-host.onion/key → your-host.onion/key
4. Move all private data from old host to your node
   (vault_blob, contact list, archived messages)
5. Flip to Host Mode
```

Now the only place that can compromise your data is a computer you own and control.

## Contrast with Email

Email providers (Gmail, Outlook, etc.):
- Store plaintext messages on servers (except TLS in transit)
- Have your password (or OAuth token) → can read everything
- Collect personal data (name, phone, recovery email)
- Can be subpoenaed or hacked
- You have no way to verify encryption

OMail:
- Stores only ciphertext (no plaintext recovery path)
- Never has your password (WebAuthn only)
- Collects no personal data
- Server compromise doesn't expose messages
- You can audit the code and run your own node
