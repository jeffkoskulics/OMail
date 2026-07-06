# User Privacy Addresses (UPAs)

OMail replaces email addresses with **User Privacy Addresses** — per-relationship cryptographic identifiers that eliminate enumeration, prevent spam, and provide relationship-level anonymity. See [concepts.md](concepts.md) for the full relationship model; this page covers the address itself.

## Format

```
<host-onion-address>.onion/<relationship-address>
```

Example:
```
3g4yxk5j2z8w9p1a4m7n2x9l5b6v3q8k.onion/7f2h9j4k6l1m3n8p2q5r7s9t2u4v6w8x
```

## Encoding

Both halves use identical encoding: `base32(pubkey || sha3-checksum || 0x03)` over an Ed25519 public key.

- **Before `.onion`**: The host's onion service address (derived from the host's Ed25519 key).
- **After `/`**: A **per-relationship address** — a freshly minted key that routes to one specific inbox on that host, reserved for one specific correspondent.

The second half is literally "another onion address without the `.onion`" — a 56-character base32 string with checksum.

## A UPA is an inbound slot

A UPA always lives on the host of the party who **receives** on it. Delivering a message to a UPA drops it into that party's inbox on that party's host.

We name a UPA `UPA-<holder>-to-<destination>`:

- **holder** keeps the address and sends *to* it,
- **destination** receives on it; the address lives on the destination's host.

So `UPA-Bob-to-Alice` is held by Bob, routes to Alice, and lives on Alice's host. To reach Alice, Bob sends to it. The reverse direction uses a *different* UPA, `UPA-Alice-to-Bob`, which lives on Bob's host. A two-OMail-user relationship therefore has two UPAs, one inbound slot per host.

## Key Properties

### Checksum Verification

Every UPA includes a SHA3-256 checksum embedded in the encoding. When a UPA is parsed, the checksum is verified immediately:

```python
from omail.upa import parse_upa

try:
    host_onion, relationship_key = parse_upa(upa_string)
except ValueError:
    print("Invalid UPA (typo or forged)")
```

Mistyped or forged addresses are rejected **before any routing happens**. This prevents accidental delivery to the wrong recipient and defends against address forgery.

### Per-Relationship Addresses

A user mints a *distinct* UPA for every correspondent — there is no single "your address." If Alice corresponds with Bob and Charlie:

```
Bob holds:      alice.onion/bob-specific-key      (mints on Alice's host)
Charlie holds:  alice.onion/charlie-specific-key  (mints on Alice's host)
```

Each is a separate inbound slot on Alice's host. Bob and Charlie cannot tell they are writing to the same person by comparing the addresses Alice gave them.

### No Enumeration

Every valid UPA is cryptographically random (one of 2^256 possibilities). Because addresses are minted per-relationship on demand, there is no directory at all. An attacker cannot:
- Scrape a list of users
- Brute-force valid addresses
- Harvest addresses for spam campaigns

Even if they compromise the server, they get opaque per-relationship keys — not a roster of identities.

## Host and Administrator addresses

The **host's own identity** uses the same key for both halves:

```
host-key.onion/host-key
```

The host's Ed25519 key serves triple duty:
1. Tor onion service identity
2. Triple Ratchet session identity (the administrator's messaging identity)
3. Cryptographic address other hosts route to

The auto-provisioned **Administrator** contact every tenant receives points at this address. Ordinary tenant-to-tenant correspondence uses per-relationship UPAs, not this master address.

## Sharing a UPA

When you mint a UPA for a correspondent, you share it out-of-band:

1. **QR code** — Fast; scan it in person or over a video call.
2. **Text copy-paste** — Long but foolproof.
3. **HTTPS link** — If you publish an invite on a website.

## Implementation

Address encoding, derivation, and parsing live in `omail.upa`:

```python
from omail.upa import (
    encode_pubkey,       # Ed25519 → UPA half
    decode_pubkey,       # UPA half → Ed25519
    derive_upa,          # Compose <host>.onion/<relationship-key>
    parse_upa,           # Parse and verify checksum
    onion_address        # Ed25519 → .onion address
)
```

The address encoding is deterministic (a given key always encodes to the same string). The *allocation* of per-relationship keys — one per correspondent — lives in the host/DB layer, not in this module.

## Contrast with Email Addresses

| Aspect | Email | UPA |
|--------|-------|-----|
| Static? | Yes — one address for everyone | No — a distinct address per relationship |
| Enumerable? | Yes — can be harvested for spam | No — minted on demand, no directory |
| Verifiable? | No — anyone can claim example@email.com | Yes — checksum prevents typos/forgery |
| Requires central authority? | Yes — registrar + MX records | No — each host mints its own |
| Tied to identity? | Yes — exposes personal data | No — relationship-level anonymity |
