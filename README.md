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

- **Cryptographic addressing (UPAs).** A User Privacy Address is a
  *per-relationship inbound address*, `<host>.onion/<relationship-address>`,
  where the second half is encoded exactly like a Tor v3 onion address (56
  base32 chars, checksummed). A user mints a distinct UPA for each
  correspondent and it lives on the receiver's host — there is no single
  static address to enumerate or spam. See [docs/concepts.md](docs/concepts.md).
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
passkey, and say `ping` to your auto-provisioned **Administrator** contact.

Tor needs a control port. The recommended torrc setup is cookie auth —
no password to manage:

```
ControlPort 9051
CookieAuthentication 1
```

(then `brew services restart tor` / `systemctl restart tor`). If your torrc
uses `HashedControlPassword` instead, set `TOR_PASSWORD` or pass
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
pytest                                    # full suite (JS interop auto-skips without node)
node scripts/browser_e2e.js              # passkey portal E2E (virtual CTAP2 + PRF)
node scripts/browser_e2e_devicekey.js    # device-key fallback E2E (no WebAuthn)
node scripts/browser_e2e_peer.js         # invite -> accept -> peer chat
node scripts/browser_e2e_guest.js        # guest invite -> claim -> Administrator chat
node scripts/browser_e2e_devicelink.js   # multi-device linking
```

## Authentication

Passkeys (WebAuthn/FIDO2) are the primary, hardware-backed path. Where a
browser has no WebAuthn at all — Tor Browser, or Chromium on a plain-http
`.onion` origin, which blocks WebAuthn as a "TLS certificate error" — the
portal offers a **device-key fallback**: the browser generates an Ed25519
key, keeps it in that browser profile, and authenticates by signing a
server challenge. It is strictly weaker than a passkey (the key is only as
safe as the browser profile) and the UI says so; it exists so onion users
are never locked out.

## Operator private onion

Alongside the public onion address (the one embedded in UPAs and shared
with contacts), each host also publishes a second, **unlisted operator
onion** that serves the same portal. Its key is generated once and
persisted, so the address is stable across restarts, and it is never
printed in QR codes or embedded in any UPA. Use it as your private door
to administer the mailbox even if the public address is being flooded.
Disable it with `--no-private-onion`.

## Guests and multi-device (see docs/concepts.md)

A **guest** is a hosted correspondent who doesn't run OMail yet (Charlie in
the docs). Their host mints a single UPA ahead of time as a one-time claim
capability; whoever opens it first completes the one credential ceremony
(passkey, falling back to device-key) that becomes their permanent
sign-in, and the invite is spent — after that, only the credential grants
access, not the link. A claimed guest is an ordinary tenant from then on
and can migrate to their own host later, same as anyone else.

Copying an identity to a **new device** is a separate, explicit action, not
a bearer link: an already-signed-in device mints a short-lived, single-use
link and uploads an encrypted parcel of the vault (keyed by a secret that
travels only in the QR/URL fragment, never seen by the server); the new
device decrypts it locally and registers its own credential against the
link. `GET /api/credentials` lists everything with access.

## Security notes (prototype)

- The host decrypts only its own Host Node conversations; user-to-user
  envelopes are routed blind. Vault blobs, ratchet states, and message
  archives are client-encrypted.
- Browsers keep decrypted material in memory for the session; the PRF
  fallback path (authenticators without PRF) stores a device-local key and
  says so loudly in the UI. The device-key auth fallback is weaker still —
  no hardware binding — and is meant for browsers that cannot do WebAuthn.
- Remote host-to-host federation over Tor is scaffolded (`queued-remote`)
  but not yet transported.
- Tor requires onion service private keys server-side; full sovereignty
  therefore requires running your own node (the migration flow says exactly
  this).
