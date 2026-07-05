"""
OMail cryptographic engine.

Modules:
  - convert:        Ed25519 <-> X25519 birational key mapping (libsodium)
  - kem:            Hybrid KEM abstraction (ML-KEM-768 post-quantum, X25519 classical)
  - triple_ratchet: Triple Ratchet protocol (DH ratchet + KEM ratchet + symmetric chains)
"""
