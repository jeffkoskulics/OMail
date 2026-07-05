# Runtime and CLI

## Entry Point

OMail is invoked via the `omail` console script, installed by `pip install -e .`:

```bash
omail --help
```

This runs `omail.cli:main`, which:
1. Parses command-line arguments
2. Initializes SQLite database
3. Provisions Tor hidden service (if `--no-tor` not set)
4. Starts aiohttp portal on 127.0.0.1
5. Renders live status and ASCII QR code
6. Waits for signals (Ctrl+C to gracefully shut down)

## Command-Line Options

```bash
omail [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--host-name` | "OMail" | Display name in portal title |
| `--port` | 8000 | HTTP listen port (127.0.0.1) |
| `--no-tor` | False | Skip Tor; run locally only |
| `--tor-password` | (env) | Tor control port password |
| `--control-port` | 9051 | Tor control port |
| `--tor-sock` | (auto) | Tor SOCKS port |
| `--db-path` | ~/.omail/ | Database directory |

### Examples

**Local development** (no Tor):

```bash
omail --no-tor --host-name "DevBox"
```

Output:
```
✓ Portal ready
  Mode: Tenant (local-only)
  URL: http://127.0.0.1:8000
  QR: [QR code]
```

Visit `http://127.0.0.1:8000` in any browser.

**Production** (with Tor):

```bash
omail --host-name "Harbor Light"
```

Requires Tor daemon running:

```bash
# Start Tor in background
tor --ControlPort 9051
```

Output:
```
✓ Portal ready
  Mode: Tenant (Tor hidden service)
  Onion: http://xyz...abc.onion
  QR: [QR code]
```

Open the `.onion` URL in Tor Browser.

**Custom port:**

```bash
omail --port 8080 --host-name "MyNode"
```

**Self-hosted (after migration):**

```bash
omail --host-name "My Sovereign Node"
```

Output:
```
✓ Portal ready
  Mode: Host
  Onion: http://new-host.onion
  UPA: new-host.onion/user-key-hash
  QR: [QR code]
```

## Portal Interface

The portal loads at the Tor address:

```
http://your-host-onion-address.onion
```

### Title Bar

```
[Host Name] OMail
```

Example: `Harbor Light OMail` (set via `--host-name`)

### Bookmark Banner

Prominently warns every visitor:

```
⚠ Bookmark this portal now.
  Onion addresses cannot be recovered or looked up — if you lose
  [your-host-onion], you lose access.
  Press Ctrl+D to save it.
```

This banner appears until dismissed (by clicking "Saved it").

### Welcome Flow

1. **Auth View**: "Create identity with a passkey" or "Sign in"
2. **Registration**: WebAuthn passkey ceremony with PRF extension
3. **Welcome Overlay**: Displays UPA, QR code, and bookmark reminder
4. **Mailbox View**: Contacts, message thread, compose box

### Session Management

- **Authentication**: WebAuthn only (no password)
- **Session token**: Stored in browser localStorage
- **Vault blob**: Downloaded on auth, decrypted with PRF key
- **Timeout**: Session expires after 30 days (or when vault_key expires)

## Database Location

By default, the database is stored at:

```bash
~/.omail/omail.db  # SQLite database
```

Override with `--db-path`:

```bash
omail --db-path /var/lib/omail/
```

Database schema:
- `users` — User identities
- `credentials` — WebAuthn credentials
- `vaults` — Encrypted private key vaults
- `messages` — Transit envelopes
- `archives` — Archived messages (encrypted)
- `contacts` — User-local contact list
- `user_prekeys` — Public prekey bundles
- `host_sessions` — Authenticated session tokens

All private key material is encrypted (`vaults` table contains opaque AES-256-GCM ciphertext).

## Tor Integration

### Hidden Service Provisioning

On startup, OMail provisions a Tor hidden service:

```python
def provision_hidden_service(ed25519_key: bytes, port: int) -> str:
    from stem import connection
    
    # Connect to Tor control port
    with connection.connect_port(control_port, password=tor_password) as tor_conn:
        # Request hidden service with specified key
        tor_conn.add_hidden_service(
            port=port,
            private_key=ed25519_key,
            version=3  # Tor v3 (56-char v2 deprecated)
        )
    
    # Compute .onion address from key
    return compute_onion_address(ed25519_key)
```

### Key Persistence

The Tor hidden service private key is stored persistently:

```bash
~/.omail/tor/hs-private-key
```

This ensures the `.onion` address doesn't change on restart.

### Control Port Authentication

Connect to Tor control port with:

```bash
# Option 1: CookieAuthentication (default if no password set)
tor --ControlPort 9051 --CookieAuthentication 1

# Option 2: Password
tor --ControlPort 9051 --HashedControlPassword "..."
omail --tor-password your-password
```

Or set environment variable:

```bash
export TOR_PASSWORD=your-password
omail
```

### Bootstrapping Status

During startup, OMail prints Tor bootstrapping progress:

```
Connecting to Tor...
  0% (connecting)
  75% (requesting descriptors)
  100% (connected)
✓ Hidden service provisioned at: xyz...abc.onion
```

If Tor is unavailable:

```
⚠ Tor connection failed (retrying...)
  Queued provisioning for next startup
  Running in local-only mode
```

On next startup, the hidden service is re-provisioned.

### Sovereign Service Re-Provisioning

After migration to self-hosting, the CLI checks for sovereign services at boot:

```python
# On startup
for user in db.users.where(mode='host'):
    ed25519_key = user.sovereign_key
    onion = provision_hidden_service(ed25519_key)
    print(f"✓ Provisioned {user.name} at {onion}")
```

This ensures that even if the Tor daemon was offline during migration, the service is re-provisioned on next startup.

## Live Status Display

During runtime, OMail prints:

```
[13:45:22] OMail Portal

  Host Name: Harbor Light
  Mode: Tenant (Tor hidden service)
  
  Onion: http://3g4yxk5j2z8w9p1a4m7n2x9l5b6v3q8k.onion
  
  Connections: 3 active sessions
  Messages: 12 pending (not including archives)
  Uptime: 2h 31m
  
  Press Ctrl+C to shutdown
```

The status updates in real-time as users connect and send messages.

## ASCII QR Code

OMail generates and displays an ASCII QR code:

```
█████████████████████████████████████████
█     ▀▄     ▄▀▄▀   ▄ ▀ ▀ ▀▄▀ ▀▄▀ ▀█
█ ▄▄▄ █ ▄▄▄▄█  █▀▄ ▀▀▄█▄▀▀▄▀▀▀▄█ ▀ █
█ █   █ ▄  ▀ ▀██▄  ▀▄▀ ▀▀▀▀▀▀▀  ▀███
█ ▀▀▀ █ ▀██▄▄█▀  ▀▀  ▀  ▀█▀ ▀▀▀▄▀ █ █
█     █ ▀▀▀▀ ▀█▀   ▀█  ▀ ▀▄▀▀  ▀▀▀▀█
█████████████████████████████████████████
  Scan with Tor Browser
```

Generated using `qrcode-generator` (bundled in `vendor.js`). The QR code encodes:

```
http://3g4yxk5j2z8w9p1a4m7n2x9l5b6v3q8k.onion
```

Users can scan with Tor Browser on mobile to quickly access their mailbox.

## Signals

### Graceful Shutdown (Ctrl+C)

Pressing Ctrl+C sends SIGINT:

```python
def signal_handler(signum, frame):
    print("Shutting down gracefully...")
    # Close WebSocket connections
    # Commit any pending database writes
    # Stop Tor hidden service (optional)
    # Exit
```

All in-flight requests are allowed to complete. Pending messages are persisted to the database.

### Configuration Reload (TBD)

Sending SIGHUP (future):

```bash
kill -HUP $(pgrep -f "omail")
```

Would reload:
- `--host-name` (update portal title)
- Tor settings (reconnect to control port)
- Database path (optional migration)

## Logging

OMail logs to stdout by default. Configure with environment variables:

```bash
export OMAIL_LOG_LEVEL=DEBUG
omail
```

Levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

Log includes:
- Portal startup/shutdown
- Tor connection status
- User registrations and authentications
- Message routing and delivery
- Errors and exceptions

## Performance Tuning

### Database

SQLite is optimized for single-writer/multiple-reader workloads (aiohttp + WebSocket subscribers):

```python
# In omail/db.py
PRAGMA journal_mode = WAL      # Write-Ahead Logging
PRAGMA synchronous = NORMAL    # Balanced performance/durability
PRAGMA cache_size = 10000      # Larger page cache
```

### Connection Pooling

aiohttp connection pool is configured for Tor:

```python
# Tor adds 1-3 second latency per hop
connector = TCPConnector(limit=100, limit_per_host=10)
```

### Message Batching

WebSocket notifications are batched to reduce overhead:

```python
# Aggregate notifications, send every 100ms
await asyncio.sleep(0.1)
```

## Monitoring

### Health Check

Simple health endpoint:

```bash
curl http://127.0.0.1:8000/health
```

Response:

```json
{
  "status": "ok",
  "mode": "tenant",
  "users": 3,
  "messages_pending": 12,
  "uptime_seconds": 9131
}
```

### Metrics Export (TBD)

Prometheus-style metrics:

```bash
curl http://127.0.0.1:8000/metrics
```

Would export:
- `omail_users_total`
- `omail_messages_sent_total`
- `omail_messages_received_total`
- `omail_ratchet_epochs_total`
- `omail_tor_connections_active`

## Deployment Scenarios

### Development

```bash
omail --no-tor --host-name "LocalDev"
```

- Fast iteration (no Tor latency)
- Local testing only
- Single-user portal

### Testing / CI

```bash
omail --no-tor --port 8000 &
pytest tests/
kill %1
```

- Tests run against live server
- No external dependencies
- Deterministic (no Tor routing variance)

### Staging / Single-User

```bash
omail --host-name "Staging" &
# Manually test via Tor Browser
```

- Full Tor integration
- Real networking
- Single user (you)

### Production / Multi-User

```bash
# Run on always-on VM or hardware
nohup omail --host-name "Production" > /var/log/omail.log 2>&1 &

# Set Tor password for control port auth
export TOR_PASSWORD=strong-password
omail --host-name "Production"
```

- 24/7 uptime
- Backup strategy (daily DB snapshots)
- Monitoring (cron job to poll `/health`)
- TLS reverse proxy optional (Tor provides encryption)

### Self-Hosted (Post-Migration)

```bash
omail --host-name "My Sovereign Node"
```

Output:
```
Mode: Host
Onion: http://my-host.onion
UPA: my-host.onion/my-key
```

Users can now share their new UPA with contacts.

## Implementation (omail/cli.py)

Core entry point:

```python
def main():
    args = parse_args()
    
    # Initialize database
    db = Database(args.db_path)
    
    # Provision Tor hidden service
    if not args.no_tor:
        tor = TorController(args.control_port, args.tor_password)
        onion = tor.provision_hidden_service(
            db.node_key,
            port=args.port
        )
    else:
        onion = f"localhost:{args.port}"
    
    # Start aiohttp server
    app = create_app(db, args.host_name)
    
    # Display status and QR code
    print_status(args.host_name, onion)
    print_qr(f"http://{onion}")
    
    # Run event loop
    asyncio.run(app.startup())
```

See `src/omail/cli.py` for full implementation.
