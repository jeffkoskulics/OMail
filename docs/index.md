# OMail System Architecture

OMail is a decentralized, privacy-first communication protocol designed to
replace legacy SMTP/IMAP infrastructure. It eliminates static addressing,
metadata exposure, and centralized plaintext relays by integrating Tor Onion
Services, hybrid post-quantum cryptography, and hardware-backed WebAuthn
mechanisms.

## User Privacy Addresses (UPAs)

```
<host-onion-address>.onion/<user-address>
```

Both halves are the same encoding: `base32(pubkey || sha3-checksum || 0x03)`
over an Ed25519 public key — the user part is literally "another onion
address without the `.onion`". Derivation and parsing live in `omail.upa`;
checksums are verified on every parse, so mistyped or forged addresses are
rejected before any routing happens.

The **host's own UPA** uses the same key for both halves: the node's onion
service key doubles as its Triple Ratchet identity (`omail.host.HostNode`).

## The Triple Ratchet

Implemented twice — `omail/crypto/triple_ratchet.py` (host, tests) and
`src/omail/static/crypto.js` (browser) — with a byte-identical wire format,
verified by cross-language interop tests.

1. **DH ratchet.** Every epoch turns a fresh X25519 exchange into new
   root/chain keys.
2. **Symmetric-key ratchet.** HMAC-SHA256 chains derive one-time
   AES-256-GCM message keys; headers are authenticated as associated data;
   out-of-order delivery is handled with banked skipped keys.
3. **KEM ratchet.** Each epoch also encapsulates a fresh ML-KEM-768 secret
   to the peer's newest KEM key and mixes it into the root KDF — the
   post-quantum leg. (A classical X25519-KEM mode exists for constrained
   peers; the algorithm is negotiated at session start.)

Sessions begin with a **PQXDH-style hybrid handshake**: three X25519
exchanges against a signed prekey bundle plus one KEM encapsulation, all
fed through HKDF.

## Zero-knowledge hosting

The host stores only:

| Table          | Contents                                              |
|----------------|-------------------------------------------------------|
| `users`        | opaque handle, UPA, Ed25519 *public* key              |
| `credentials`  | WebAuthn credential IDs + COSE public keys            |
| `vaults`       | AES-GCM blobs encrypted with the passkey-PRF key      |
| `messages`     | transit ratchet envelopes → client-encrypted archives |
| `user_prekeys` | *public* prekey bundles (private halves in the vault) |

The vault key is derived from the WebAuthn **PRF extension** output — a
secret evaluated inside the user's authenticator that never reaches the
server. When a client consumes an incoming envelope it uploads a
vault-encrypted archive and the plaintext-bearing envelope is destroyed
(`POST /api/messages/{id}/archive`).

Onboarding collects **no personal data**: no email, no password, no name.

## Message flow

```
Tor Browser ──http over onion──► 127.0.0.1:8000 (aiohttp)
   │ passkey ceremonies (fido2)          │
   │ vault blobs (opaque)                │
   │ ratchet envelopes ─────────────────►│── is_host? host ratchet replies
   │                                     │── local UPA? blind delivery + WS push
   │◄──────────── WebSocket notify ──────│── remote UPA? queued (federation TBD)
```

## Self-hosting migration

`POST /api/migrate` (portal: **⚑ Become Your Own Host**):

1. generates an independent Ed25519 onion identity for the user,
2. publishes a dedicated hidden service (immediately if Tor is reachable,
   otherwise on next launch — the CLI re-provisions sovereign services at
   boot),
3. rewrites the UPA routing header `<host>.onion/<key>` → `<own>.onion/<key>`
   (the user key half never changes),
4. flips the node config from Tenant Mode to Host Mode and prints the
   updated routing table on the terminal.

## Runtime

`omail` (console script → `omail.cli:main`) starts the async portal bound
to `127.0.0.1:8000`, provisions the Tor Hidden Service via the control
port (`stem`), and renders real-time status plus an ASCII QR code of the
`.onion` URL. The portal's `<title>` is `[Host Name] OMail`, and a
bookmark-enforcement banner reminds every visitor that an onion address
lost is a mailbox lost.
