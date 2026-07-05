"""
OMail — decentralized, privacy-first messaging over Tor.

Core components:
  - omail.key_pair       Ed25519 identity key pairs
  - omail.onion_service  Tor v3 Onion Service management (stem)
  - omail.upa            User Privacy Address derivation and parsing
  - omail.crypto         Triple Ratchet engine, hybrid KEM, key conversion
  - omail.db             SQLite persistence (encrypted vaults, envelopes)
  - omail.webauthn       Passkey (WebAuthn/FIDO2) ceremonies with PRF support
  - omail.host           Host-node identity, bootstrap contact, ratchet peer
  - omail.migration      Tenant -> sovereign host promotion
  - omail.server         aiohttp portal and messaging API
  - omail.cli            `omail` terminal entry point
"""

__version__ = "0.1.0"
