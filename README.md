# OMail

**Private asynchronous messaging featuring User Privacy Addresses for individual
contacts.** It's like email with Authentication, Confidentiality, Integrity,
anti-Doxxing and anti-Spam built in — rebuilt from first principles instead of
patched onto 1970s SMTP.

```
   ____  __  __       _ _
  / __ \|  \/  | __ _(_) |
 | |  | | |\/| |/ _` | | |    decentralized - private - sovereign
 | |__| | |  | | (_| | | |
  \____/|_|  |_|\__,_|_|_|
```

## Core tenets

- **Cryptographic addressing (UPAs).** A User Privacy Address is
  `<host>.onion/<user-address>`, where the user part is the user's Ed25519
  public key encoded exactly like a Tor v3 onion address (56 base32 chars,
  checksummed). No memorable static addresses, nothing to enumerate, nothing
  to spam.
- **Transport & metadata anonymity.** The portal binds to `127.0.0.1` and is
  reached exclusively through a Tor Hidden Service the node provisions at
  startup. The host's onion key *is* its messaging identity.
- **Hardware-backed zero knowledge.** Passkeys (WebAuthn/FIDO2) are the sole
  authentication mechanism — no email, no password, no personal data. The
  WebAuthn **PRF extension** derives a vault key inside the authenticator;
  user private keys reach the host only as AES-GCM ciphertext.
- **Triple Ratchet encryption.** Signal-style DH ratchet + per-message
  symmetric chains + a third **KEM ratchet** that mixes an **ML-KEM-768**
  (FIPS 203) shared secret into every epoch, for forward secrecy and
  post-compromise security against classical *and* quantum adversaries.
  Sessions start with a PQXDH-style hybrid handshake against signed prekey
  bundles.
- **Dynamic node sovereignty.** Every tenant has a "Become Your Own Host"
  action that mints an independent onion service, rewrites their UPA routing,
  and confirms the new routing table on the host terminal.

## Quick start

```bash
pip install -e .
omail --host-name "Harbor Light"          # requires a running Tor daemon
omail --no-tor                            # local development mode
```

The terminal prints live status and an ASCII QR code of the generated
`.onion` portal URL. Open it in Tor Browser, create an identity with a
passkey, and say `ping` to your auto-provisioned **Host Node** contact.

Tor needs a control port; either set `TOR_PASSWORD` or pass
`--tor-password` (see `--control-port`, default 9051).

## Repository layout

```
src/omail/
  cli.py               omail entry point: portal + Tor bootstrap + status/QR
  server.py            aiohttp portal & messaging API (WebSocket push)
  host.py              host identity, prekey bundles, host-side ratchets
  migration.py         tenant -> sovereign host promotion
  webauthn.py          passkey ceremonies (python-fido2), PRF-aware flows
  db.py                SQLite persistence (opaque vaults & envelopes only)
  upa.py               User Privacy Address derivation/parsing
  key_pair.py          Ed25519 key pairs
  onion_service.py     Tor v3 onion services via stem
  crypto/
    triple_ratchet.py  the Triple Ratchet protocol + hybrid handshake
    kem.py             ML-KEM-768 and X25519-KEM
    convert.py         Ed25519 <-> X25519 birational mapping
  static/
    crypto.js          wire-compatible JS Triple Ratchet (browser client)
    app.js             portal client (passkeys, PRF vault, mailbox)
    vendor.js          bundled tweetnacl + ed2curve + noble ML-KEM + QR
tests/                 89 tests incl. JS<->Python ratchet interop
scripts/browser_e2e.js Playwright E2E (virtual CTAP2 authenticator with PRF)
```

## Testing

```bash
pytest                          # full suite (JS interop auto-skips without node)
node scripts/browser_e2e.js     # headless-Chromium end-to-end portal test
```

## Security notes (prototype)

- The host decrypts only its own Host Node conversations; user-to-user
  envelopes are routed blind. Vault blobs, ratchet states, and message
  archives are client-encrypted.
- Browsers keep decrypted material in memory for the session; the PRF
  fallback path (authenticators without PRF) stores a device-local key and
  says so loudly in the UI.
- Remote host-to-host federation over Tor is scaffolded (`queued-remote`)
  but not yet transported.
- Tor requires onion service private keys server-side; full sovereignty
  therefore requires running your own node (the migration flow says exactly
  this).
