# Self-Hosting Migration

OMail is designed for users to migrate from a shared public node to their own sovereign server at any time, without downtime or message loss.

## Why Self-Host?

By default, your mailbox lives on a shared public node. This is convenient, but:

- **Operator dependency**: The node could shut down, migrate, or be compromised
- **Limited sovereignty**: Your identity lives on someone else's infrastructure
- **Metadata sharing**: Other users' activity on the same node could leak information about your usage patterns

Self-hosting means:
- **Full control**: You run the server; you control the identity
- **True sovereignty**: No operator can revoke your identity or access
- **Isolation**: No shared infrastructure or metadata leakage
- **Auditability**: You can inspect and modify the exact code running on your server

## How Migration Works

Clicking **⚑ Become Your Own Host** in the mailbox portal triggers a multi-step process:

```
POST /api/migrate
  → { new_onion, new_upa, routing_table }
```

### Step 1: Generate Sovereign Identity

The current host generates a new Ed25519 key for the user:

```python
def promote_to_sovereign(user_id: int) -> dict:
    new_key = Ed25519.generate()  # Independent identity
    return {
        'new_ed25519_key': new_key,
        'onion_address': onion_address(new_key),
        'upa': derive_upa(new_key, new_key),  # Host's own UPA
    }
```

This key is:
- Ed25519 private key (sent to user's device)
- Used as Tor v3 onion service identity
- Used as the Triple Ratchet master key
- Becomes the user's new `host.onion` address

### Step 2: Provision Tor Hidden Service

If Tor is reachable, a hidden service is provisioned immediately:

```python
def provision_onion_service(ed25519_key: bytes, port: int) -> str:
    from stem import SocketError, connection
    
    with connection.connect_port(tor_port) as tor_conn:
        # Add hidden service with user's key
        tor_conn.add_hidden_service(
            port=port,
            private_key=ed25519_key,
            version=3  # Tor v3 (v2 deprecated)
        )
        return onion_address(ed25519_key)  # e.g., "abc...xyz.onion"
```

If Tor is not reachable, the service is provisioned on next startup (the CLI checks and re-provisions sovereign services at boot).

### Step 3: Migrate All User Data

All encrypted data is migrated to the user's new server:

```python
def migrate_data(old_user_id: int, new_server_key: bytes) -> dict:
    user = db.users.get(old_user_id)
    
    # Migrate vault (contains all private keys and ratchet state)
    vault_blob = db.vaults.get(user_id=old_user_id)
    
    # Migrate archived messages
    archives = db.archives.get(user_id=old_user_id)
    
    # Migrate prekey bundles
    prekeys = db.user_prekeys.get(user_id=old_user_id)
    
    # Migrate contacts (local-only references, no need to sync)
    contacts = db.contacts.get(user_id=old_user_id)
    
    return {
        'vault_blob': vault_blob,
        'archives': archives,
        'prekeys': prekeys,
        'contacts': contacts,
    }
```

All data remains encrypted (vault key was derived from user's passkey, not the server).

### Step 4: Rewrite UPA Routing

The user's UPA is updated to point to the new host:

```
Before migration:
  old-host.onion/user-key-hash

After migration:
  new-host.onion/user-key-hash
  (same user-key-hash, new host-part)
```

The "user-key-hash" half of the UPA never changes (it's derived from the user's key). Only the "host" half changes.

### Step 5: Flip to Host Mode

The node configuration is updated:

```yaml
# Before
node_mode: tenant
hosted_on: old-host.onion

# After
node_mode: host
own_identity: new-host-ed25519-key
own_onion: new-host.onion
own_upa: new-host.onion/user-key-hash
```

The old host can (optionally) be informed to forward incoming messages to the new address.

### Step 6: Terminal Confirmation

The CLI prints the updated routing table:

```
✓ Migration Complete
┌──────────────────────────────────┐
│ OLD UPA (for reference)          │
│ old-host.onion/abc...xyz         │
├──────────────────────────────────┤
│ NEW UPA (share this)             │
│ new-host.onion/abc...xyz         │
├──────────────────────────────────┤
│ Onion address (copy to Tor Browser) │
│ http://new-host.onion            │
└──────────────────────────────────┘

Running in Host Mode.
Mailbox is at: new-host.onion/abc...xyz
Remember: This server must stay online to receive messages.
```

## After Migration

### Updating Contacts

Contacts need to update your address in their contact list:

```
Old UPA: old-host.onion/user-key-hash
New UPA: new-host.onion/user-key-hash
```

Since the "user-key-hash" half doesn't change, contacts can derive the new UPA deterministically (if they have your Ed25519 public key). But for simplicity, OMail recommends explicitly sharing the new UPA.

### Messages in Transit

Messages sent to the old UPA might still arrive:
- If the old host is still running, it can forward
- If the old host is offline, messages are lost (recommend old host to have a forwarding rule)
- New messages must use the new UPA

### Running the Server

Your device must run the OMail node 24/7 to receive messages:

```bash
# On your always-on computer (Raspberry Pi, cloud VM, etc.)
omail --host-name "My Sovereign Node"
```

The node:
- Provisions a Tor hidden service
- Binds to 127.0.0.1:8000 (Tor routes external traffic)
- Persists the onion private key (survives restarts)
- Prints the `.onion` URL for bookmarking

### Backup Strategy

Your new server should:
- Run on a stable platform (not a laptop that gets shut down)
- Have automated backups (SQLite can be backed up while running)
- Have a monitoring script (e.g., cron job to ping the node)
- Have a fallback (e.g., redeploy if the server crashes)

Example backup:

```bash
#!/bin/bash
# Backup the database daily
tar czf ~/backups/omail-db-$(date +%Y%m%d).tar.gz ~/.omail/

# Push to remote storage (e.g., B2, S3, rsync)
rclone sync ~/backups/ remote:backups/
```

## Implementation Details

See `omail/migration.py`:

```python
from omail.migration import promote_to_sovereign

@app.post("/api/migrate")
async def migrate_endpoint(user_id: int):
    # 1. Generate new Ed25519 key
    new_key = promote_to_sovereign(user_id)
    
    # 2. Provision Tor hidden service
    onion = provision_onion_service(new_key.private)
    
    # 3. Migrate all encrypted data
    migrate_data(user_id, new_key)
    
    # 4. Flip to Host Mode
    flip_to_host_mode(user_id, new_key)
    
    # 5. Return routing info
    return {
        "new_upa": derive_upa(new_key, new_key),
        "onion_address": onion,
        "routing_table": print_routing_table(new_key),
    }
```

## Security Considerations

### Authenticator Compromise

If your authenticator is compromised during migration:
- The vault key (PRF output) could be extracted
- An attacker could decrypt your vault_blob
- **Mitigation**: Use a hardware security key (YubiKey) which is harder to compromise

### Server Compromise After Migration

If your sovereign node is hacked:
- Attacker gains access to the database
- They get the same opaque vault_blob (encrypted with vault_key)
- The vault key is in your authenticator, not on the server
- **Mitigation**: Run the node in a secure environment (VM, isolated hardware)

### Network Compromise

If your Tor exit node is malicious:
- They see you're accessing your mailbox (timing + volume metadata)
- They cannot read the content (end-to-end encrypted)
- **Mitigation**: OMail routing is already blind; use multiple Tor paths

### Key Loss

If you lose access to your authenticator (stolen, broken, lost):
- You lose access to the vault key
- Your mailbox becomes inaccessible
- No recovery mechanism
- **Mitigation**: Back up your authenticator (biometric + security key, or multiple keys)

## Federation Between Nodes

If two users run sovereign nodes, they can message each other:

```
Alice's node:          Bob's node:
  alice.onion/key  ←—→  bob.onion/key
    (via Tor)
```

OMail uses blind routing and onion service addressing, so no third party can observe the communication. Federation is currently scaffolded in `omail/server.py` as `queued-remote`; full implementation is TBD.

## Multi-User Hosting

One node can host multiple users (like a private mail server):

```
my-server.onion/alice-key
my-server.onion/bob-key
my-server.onion/charlie-key
```

Each user has:
- Independent Ed25519 key (no shared master key)
- Encrypted vault (vault_key is their passkey's PRF output)
- Independent prekey bundles
- Separate message archives

The server operator can:
- See opaque envelopes (can't read content)
- See UPA addresses (can't link to real identity)
- See message volume/timing (metadata)

The server operator cannot:
- Read message content (end-to-end encrypted)
- Forge messages (Ed25519 signatures)
- Impersonate users (keys in encrypted vault)

## Troubleshooting

### Tor Connection Failed

```
Error: Cannot connect to Tor control port (9051)
```

**Solution**: Start Tor daemon or set `--tor-password`:

```bash
tor --ControlPort 9051 --CookieAuthentication 1
# OR
omail --tor-password your-password
```

### Port Already in Use

```
Error: Address already in use (127.0.0.1:8000)
```

**Solution**: Use a different port:

```bash
omail --port 8001
```

### Hidden Service Not Provisioning

```
Warning: Hidden service provisioning failed
Retrying on next startup...
```

**Solution**: The node will retry when restarted. Ensure Tor daemon is running and the control port is reachable.

## Contrast with Email Self-Hosting

Email self-hosting is notoriously hard:
- Requires DNS setup, SPF, DKIM, DMARC (months of configuration)
- Requires static IP address (many ISPs don't allow port 25)
- Requires spam filtering and rate limiting
- Sender reputation matters (your mail might be filtered)

OMail self-hosting is simpler:
- No DNS records needed (Tor v3 onion is permanent)
- No ISP port restrictions (Tor uses standard HTTPS)
- No spam filtering needed (only connected users can message you)
- No sender reputation (cryptographic verification, not heuristic)

Just run the node and share your UPA.
