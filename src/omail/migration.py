"""
Self-hosting migration: Tenant Mode -> Host Mode.

"Become Your Own Host" promotes a tenant to a sovereign node:

  1. An independent Ed25519 onion identity is generated for the user.
  2. A dedicated Tor Hidden Service is provisioned for it (when a Tor
     controller is reachable).
  3. The user's UPA routing header is rewritten from
     <host-onion>/<user-key> to <own-onion>/<user-key>.
  4. The node's routing table is confirmed on the terminal.

Note on trust: Tor requires the onion service key on the machine that
publishes the descriptor, so sovereignty is only fully realized when the
user runs this node themselves. The migration output says so explicitly.
"""
from typing import Callable, Optional

from cryptography.hazmat.primitives import serialization

from omail.db import Database
from omail.host import HostNode
from omail.key_pair import KeyPair
from omail.onion_service import OnionService
from omail.upa import derive_upa, onion_address

Announce = Callable[[str], None]


def promote_to_sovereign(
    db: Database,
    host: HostNode,
    user_id: int,
    announce: Announce = print,
    control_port: int = 9051,
    tor_password: Optional[str] = None,
    local_port: int = 8000,
    start_tor_service: bool = True,
) -> dict:
    """Promotes a tenant to a sovereign self-hosted identity.

    Returns {"onion", "upa", "old_upa", "tor_active"}.
    """
    user = db.get_user(user_id)
    if user is None:
        raise ValueError("Unknown user")
    if user["sovereign"]:
        raise ValueError("User is already sovereign")

    old_upa = user["upa"]

    # 1. Independent onion identity for the promoted node
    onion_kp = KeyPair()
    onion_kp.generate_key_pair()
    new_onion = onion_address(onion_kp.public_key)
    db.set_config(f"sovereign_onion_key:{user_id}", onion_kp.get_private_str())

    # 2. Dedicated hidden service (best effort: requires a running Tor)
    tor_active = False
    if start_tor_service:
        try:
            service = OnionService(
                onion_kp,
                target_port=local_port,
                control_port=control_port,
                password=tor_password,
            )
            service.start()
            tor_active = True
        except Exception as exc:  # Tor unreachable: routing still updates
            announce(f"[migration] Tor controller unavailable ({exc}); "
                     "onion service will start on next node launch.")

    # 3. Rewrite UPA routing
    new_upa = derive_upa(new_onion, bytes(user["identity_pub"]))
    db.update_user_upa(user_id, new_upa, sovereign=True)
    db.set_config("mode", "host")

    # 4. Terminal confirmation of the new routing tables
    announce("=" * 62)
    announce("SELF-HOSTING MIGRATION COMPLETE — node shifted to HOST MODE")
    announce("-" * 62)
    announce(f"  user handle     : {user['handle']}")
    announce(f"  new onion       : {new_onion}")
    announce(f"  routing table   : {old_upa}")
    announce(f"                 -> {new_upa}")
    announce(f"  tor service     : {'LIVE (descriptor published)' if tor_active else 'pending next launch'}")
    announce(f"  tenancy on      : {host.onion} retained as fallback relay")
    announce("  NOTE: export this node's data directory to hardware you")
    announce("  control to complete physical sovereignty.")
    announce("=" * 62)

    return {
        "onion": new_onion,
        "upa": new_upa,
        "old_upa": old_upa,
        "tor_active": tor_active,
    }
