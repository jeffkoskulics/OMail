"""
onion_service.py

Handles the creation and management of ephemeral Tor Onion Services
using the stem library and KeyPair identities.
"""
import base64
from typing import Optional
from stem.control import Controller
from cryptography.hazmat.primitives import serialization
from key_pair import KeyPair

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
        control_port: int = 9051
    ) -> None:
        """
        Initializes the OnionService.

        Args:
            key_pair: The KeyPair identity for the service.
            target_port: The local port where the actual service is running.
            hidden_service_port: The port exposed to the Tor network (default 80).
            control_port: The Tor control port (default 9051).
        """
        self.key_pair = key_pair
        self.target_port = target_port
        self.hidden_service_port = hidden_service_port
        self.control_port = control_port
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
        
        # Stem expects the key content to be Base64 encoded
        key_content = base64.b64encode(private_bytes).decode('utf-8')

        # Connect to Tor
        self.controller = Controller.from_port(port=self.control_port)
        self.controller.authenticate()  # Auto-detects cookie or password auth

        # Create the service
        # await_publication=True ensures the descriptor is uploaded before returning
        response = self.controller.create_ephemeral_hidden_service(
            {self.hidden_service_port: self.target_port},
            key_type="ED25519-V3",
            key_content=key_content,
            await_publication=True
        )

        self.service_id = response.service_id
        return self.service_id

    def stop(self) -> None:
        """
        Stops the Onion Service.

        Removes the ephemeral service from the Tor controller and closes the connection.
        """
        if self.controller and self.service_id:
            try:
                self.controller.remove_ephemeral_hidden_service(self.service_id)
            except Exception:
                # If connection is already dead or service gone, ignore
                pass
            finally:
                self.controller.close()
                self.controller = None
                self.service_id = None