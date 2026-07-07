# OMail Concepts and Terminology

This is the canonical glossary for OMail. Other documents defer to the
definitions here.

## Roles and infrastructure

| Term | Meaning |
|------|---------|
| **Host** | The server — the hardware and OMail node process that stores accounts, routes envelopes, and runs the portal. A host is reached through its Tor onion service. |
| **Administrator** | The operator of a host — exactly one per host. The Administrator signs in through the host's **admin onion** (below) and gets an email-client view: Inbox, Sent, Drafts, and Contacts. |
| **Tenant** | An account on a host. This includes the Administrator's own account and any **guest** the host is carrying. Tenants are expected to be temporary — the endgame is that each tenant graduates to administering a host of their own. |
| **Guest** | A correspondent who does not (yet) run OMail and is hosted on someone else's host, reachable through a webmail interface. Charlie in the examples below. |
| **Echo Test** | The auto-provisioned first contact every new tenant gets: a deterministic responder (`ping` → `pong`) for confirming the encryption pipeline end-to-end before any real contact exists. A diagnostic bot, not a person. |

A single Ed25519 key is the host's identity: it is simultaneously the Tor
v3 onion service key and the host's own messaging identity.

## The two doors: public onion vs. admin onion

Every host publishes **two** Tor onion services, backed by different keys
and serving different audiences:

- **Public onion** — the host's identity. This is the address embedded in
  UPAs and invite links; contacts, peer hosts, and guests all connect here.
- **Admin onion** — the operator's private door, printed on the host's
  terminal at boot (`http://…onion`, a bare address — not a UPA). It is
  never embedded in any UPA, invite, or page served to others; the only
  place it exists is the operator's terminal and bookmark.

The first visit to the admin onion shows a one-time setup screen; the
credential created there (passkey or device key) becomes the host's one
and only Administrator, and the screen never appears again — afterwards
the admin onion is login-only. Registration and sign-in for everyone else
happen exclusively on the public onion; the node rejects tenant
registration on the admin door and admin sign-in on the public door.

## User Privacy Addresses (UPAs)

A **UPA** is a *per-relationship inbound address*. It has the form:

```
<host-onion-address>.onion/<relationship-address>
```

Key properties:

- **Per-relationship, not per-user.** A user mints a *distinct* UPA for
  every correspondent. There is no single "your address" to hand out.
- **Inbound slot on the recipient's host.** A UPA always lives on the host
  of the party who *receives* on it. Delivering to a UPA drops the message
  into that party's inbox on that party's host.
- **Checksummed onion-style encoding.** The relationship-address half is
  encoded exactly like a Tor v3 onion address (`base32(pubkey || sha3
  checksum || version)`), so typos and forgeries are rejected on parse.

### Naming convention

We write a UPA as `UPA-<holder>-to-<destination>`:

- **holder** — the party who keeps and sends *to* the address.
- **destination** — the party who receives on it; the address lives on the
  destination's host.

So `UPA-Bob-to-Alice` is held by Bob, routes to Alice, and lives on
Alice's host.

## Establishing a relationship

Alice doesn't need to know in advance whether a correspondent runs their
own OMail host. She mints **one unified invite** — a single UPA — and
whoever receives it decides which of the two paths below to take, simply
by how they use it:

- **paste it into their own host's "Accept invite" box** → the peer flow
  (Alice ↔ Bob), or
- **open it directly as a link** → the guest claim flow (Alice ↔ Charlie).

Both paths share the exact same address, so Alice shares one thing —
either the raw UPA or the clickable link both work everywhere: an
"Accept invite" box also accepts the full link (it extracts the address
automatically), and the link itself works even if only the bare address
gets passed along. Whichever path happens first wins; the invite is
single-use either way, and Alice's contact list updates automatically
the moment either one completes — no separate acceptance step on her side.

### Two OMail users (Alice ↔ Bob)

Both Alice and Bob administer their own hosts.

1. Alice wants to reach Bob. Alice's host **mints `UPA-Bob-to-Alice`** — an
   inbound slot on Alice's host, reserved for Bob — and Alice shares it
   with Bob out-of-band (QR code, link, etc.).
2. Bob adds `UPA-Bob-to-Alice` to his host. Behind the scenes **Bob's host
   reaches out to Alice's host** to establish the connection.
3. As part of that handshake, **Bob's host mints `UPA-Alice-to-Bob`** — an
   inbound slot on *Bob's* host, reserved for Alice — and **sends it to
   Alice's host**, which acknowledges receipt. Bob's host mints this one
   because Bob must hold its private keys.
4. Now the relationship is symmetric:
   - To write to Alice, Bob sends to `UPA-Bob-to-Alice` (lands on Alice's host).
   - To write to Bob, Alice sends to `UPA-Alice-to-Bob` (lands on Bob's host).

Each side holds two addresses per relationship: the inbound slot it minted
on its own host, and the outbound handle it received for the peer's host.

### An OMail user and a guest (Alice ↔ Charlie)

Charlie does not run OMail. Alice hosts Charlie.

1. Alice's host mints **`UPA-Charlie-to-Alice`** — the single UPA the
   relationship needs — and shares it with Charlie out-of-band.
2. Charlie reaches Alice through a **webmail interface Alice's host serves**
   for him. Messages Charlie sends arrive at `UPA-Charlie-to-Alice` on
   Alice's host.
3. Messages Alice sends to Charlie **remain on Alice's host** until Charlie
   reads them in webmail (store-on-sender). Because there is no second host
   to route to, **no `UPA-Alice-to-Charlie` is needed**.

### Graduation: a guest becomes a host

If Charlie later stands up his own OMail host, he supplies Alice with
**`UPA-Alice-to-Charlie`** — an inbound slot on Charlie's new host. From
then on the relationship behaves exactly like Alice ↔ Bob, and Alice's
messages route to Charlie's host instead of waiting in webmail.

In implementation terms this needs no guest-specific machinery: Charlie
runs the ordinary self-hosting migration (`POST /api/migrate`), then mints
`UPA-Alice-to-Charlie` the same way any tenant creates a relationship
invite, and Alice accepts it exactly as she would from Bob. A claimed guest
is, from that point on, indistinguishable from any other tenant.

## Why this shape

- **No enumerable directory.** Because addresses are per-relationship and
  minted on demand, there is no single identifier to harvest or spam.
- **Unlinkability.** Two of your correspondents cannot tell they are
  writing to the same person by comparing the addresses you gave them.
- **Sovereignty gradient.** A guest costs their host almost nothing and can
  graduate to full independence without breaking the relationship.
