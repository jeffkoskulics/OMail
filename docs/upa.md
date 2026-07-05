# User Privacy Addresses (UPAs)

OMail replaces email addresses with **User Privacy Addresses** — cryptographic identifiers that eliminate enumeration, prevent spam, and provide contact-specific anonymity.

## Format

```
<host-onion-address>.onion/<user-address>
```

Example:
```
3g4yxk5j2z8w9p1a4m7n2x9l5b6v3q8k.onion/7f2h9j4k6l1m3n8p2q5r7s9t2u4v6w8x
```

## Encoding

Both halves use identical encoding: `base32(pubkey || sha3-checksum || 0x03)` over an Ed25519 public key.

- **Before `.onion`**: The mailbox host's onion service address (derived from host's Ed25519 key)
- **After `/`**: The user's identity on that host (also derived from Ed25519, but contact-specific)

The user part is literally "another onion address without the `.onion`" — a 56-character base32 string with checksum.

## Key Properties

### Checksum Verification

Every UPA includes a SHA3-256 checksum embedded in the encoding. When a UPA is parsed, the checksum is verified immediately:

```python
from omail.upa import parse_upa

try:
    host, user_key = parse_upa(upa_string)
except ValueError:
    print("Invalid UPA (typo or forged)")
```

Mistyped or forged addresses are rejected **before any routing happens**. This prevents accidental delivery to the wrong recipient and defends against address forgery.

### Contact-Specific Addresses

The same person gets a different UPA for each contact. If you share your UPA with Alice and Bob:

```
Alice sees:  host.onion/alice-specific-hash
Bob sees:    host.onion/bob-specific-hash
```

Both hash to your key, but observers cannot tell they're the same person by comparing addresses.

### No Enumeration

Every valid UPA is cryptographically random (one of 2^256 possibilities). An attacker cannot:
- Scrape a directory of users
- Brute-force valid addresses
- Harvest addresses for spam campaigns

Even if they compromise the server, they get opaque hashes — not a list of contacts or identities.

## Host's Own UPA

The **host's own UPA** uses the same key for both halves:

```
host-key.onion/host-key
```

This is the node's master identity. The host's Ed25519 key serves triple duty:
1. Tor onion service identity
2. Triple Ratchet session identity (for responding to messages)
3. Cryptographic address (for receiving messages from other hosts)

## Sharing a UPA

Users share UPAs in three ways:

1. **Text copy-paste** — Long but foolproof
2. **QR code** — Fast, but must be transmitted out-of-band
3. **HTTPS link** — If published on a website

## Implementation

Derivation and parsing live in `omail.upa`:

```python
from omail.upa import (
    encode_pubkey,       # Ed25519 → UPA half
    decode_pubkey,       # UPA half → Ed25519
    derive_upa,          # Deterministic UPA from keys
    parse_upa,           # Parse and verify checksum
    onion_address        # Ed25519 → .onion address
)
```

All operations are deterministic: the same key always produces the same UPA. This allows contacts to independently verify that a UPA belongs to a specific person (out-of-band confirmation).

## Contrast with Email Addresses

| Aspect | Email | UPA |
|--------|-------|-----|
| Static? | Yes — compromises privacy | No — different per contact |
| Enumerable? | Yes — can be harvested for spam | No — cryptographically random |
| Verifiable? | No — anyone can claim example@email.com | Yes — checksum prevents typos/forgery |
| Requires central authority? | Yes — registrar + MX records | No — derived from user's key |
| Tied to identity? | Yes — exposes personal data | No — contact-specific anonymity |
