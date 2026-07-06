"""
onion_service.py

Handles the creation and management of ephemeral Tor Onion Services
using the stem library and KeyPair identities.
"""
import base64
import hashlib
from typing import Optional
from stem import SocketError, ControllerError
from stem.control import Controller
from cryptography.hazmat.primitives import serialization
from omail.key_pair import KeyPair
from omail.upa import encode_pubkey


def _tor_expanded_private_key(seed: bytes) -> bytes:
    """Converts a 32-byte Ed25519 seed to Tor's ED25519-V3 key blob.

    Tor's ADD_ONION expects the 64-byte *expanded* secret key: the
    SHA-512 hash of the seed with the scalar half clamped (RFC 8032 /
    ed25519-donna style). Sending anything else — e.g. seed||public —
    makes Tor treat the first 32 bytes as the scalar and publish the
    service under a completely different .onion address than the one
    derived from the seed's true public key.
    """
    if len(seed) != 32:
        raise ValueError("Expected a raw 32-byte Ed25519 seed")
    h = hashlib.sha512(seed).digest()
    scalar = bytearray(h[:32])
    scalar[0] &= 248
    scalar[31] &= 63
    scalar[31] |= 64
    return bytes(scalar) + h[32:]

class OnionService:
    """
    Manages a Tor Onion Service (Hidden Service).

    Uses an Ed25519 KeyPair to create a v3 Onion Service via the Tor
    Control Port.
    """

    def __init__(
        self,
        key_pair: KeyPair,
        target_port: int,
        hidden_service_port: int = 80,
        control_port: int = 9051,
        password: Optional[str] = None
    ) -> None:
        """
        Initializes the OnionService.

        Args:
            key_pair: The KeyPair identity for the service.
            target_port: The local port where the actual service is running.
            hidden_service_port: The port exposed to the Tor network (default 80).
            control_port: The Tor control port (default 9051).
            password: The password for the Tor control port (default None).
        """
        self.key_pair = key_pair
        self.target_port = target_port
        self.hidden_service_port = hidden_service_port
        self.control_port = control_port
        self.password = password
        self.service_id: Optional[str] = None
        self.controller: Optional[Controller] = None

    def start(self) -> str:
        """
        Starts the Ephemeral Onion Service.

        Connects to the Tor controller, authenticates, and creates the service
        using the private key from the KeyPair.

        Returns:
            str: The .onion address (service ID) without the '.onion' suffix.
        """
        if not self.key_pair.private_key:
            raise ValueError("Cannot start service: KeyPair has no private key.")

        # Extract the raw 32-byte private key seed for Ed25519
        private_bytes = self.key_pair.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_bytes = self.key_pair.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Stem expects the key content to be Base64 encoded
        key_content = base64.b64encode(
            _tor_expanded_private_key(private_bytes)
        ).decode('utf-8')

        # Connect to Tor
        self.controller = Controller.from_port(port=self.control_port)
        self.controller.authenticate(password=self.password)

        # Create the service
        # await_publication=True ensures the descriptor is uploaded before returning
        response = self.controller.create_ephemeral_hidden_service(
            {self.hidden_service_port: self.target_port},
            key_type="ED25519-V3",
            key_content=key_content,
            await_publication=True
        )

        # The service_id Tor returns is the authoritative address. It must
        # match the address we derive (and print, and embed in UPAs) from
        # the public key — otherwise users are sent to a dead .onion.
        expected = encode_pubkey(public_bytes)
        if response.service_id != expected:
            self.controller.remove_ephemeral_hidden_service(response.service_id)
            self.controller.close()
            self.controller = None
            raise RuntimeError(
                f"Tor published {response.service_id}.onion but this node "
                f"derives {expected}.onion — key format mismatch"
            )

        self.service_id = response.service_id
        return self.service_id

    def stop(self) -> None:
        """
        Stops the Onion Service.

        Removes the ephemeral service from the Tor controller and closes the connection.
        """
        if self.controller:
            if self.service_id:
                try:
                    self.controller.remove_ephemeral_hidden_service(self.service_id)
                except (ControllerError, SocketError):
                    # If connection is already dead or service gone, ignore
                    pass
            
            self.controller.close()
            self.controller = None
            self.service_id = None