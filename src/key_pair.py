import base64
from typing import Any, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class KeyPair:
    """
    Represents an Ed25519 public/private key pair for asymmetric cryptography.

    This class handles generation, serialization (PEM format), and validation
    of the key pair.
    """
    def __init__(self) -> None:
        """Initializes an empty KeyPair instance."""
        self.private_key: Optional[ed25519.Ed25519PrivateKey] = None
        self.public_key: Optional[ed25519.Ed25519PublicKey] = None

    def _validate(self, private_key: Any, public_key: Any) -> bool:
        """
        Validates that the public key corresponds to the private key.

        Args:
            private_key: The private key object.
            public_key: The public key object.

        Returns:
            bool: True if the keys match.

        Raises:
            ValueError: If the public key does not belong to the private key.
        """
        # Derived public key from the private key
        derived_pub = private_key.public_key()
        
        # Compare raw bytes
        raw_provided = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        raw_derived = derived_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        if raw_provided != raw_derived:
            raise ValueError("Key-pair mismatch: Public key does not belong to Private key.")
        return True

    def generate_key_pair(self) -> None:
        """
        Generates a new valid Ed25519 key pair.

        The generated keys are stored in the instance attributes.
        """
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        
        # Assign to attributes
        self.private_key = priv
        self.public_key = pub

    def get_private_str(self) -> Optional[str]:
        """
        Returns the private key as a PEM-encoded string.

        Returns:
            Optional[str]: The PEM-encoded private key, or None if not set.
        """
        if not self.private_key:
            return None
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

    def get_public_str(self) -> Optional[str]:
        """
        Returns the public key as a PEM-encoded string.

        Returns:
            Optional[str]: The PEM-encoded public key, or None if not set.
        """
        if not self.public_key:
            return None
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def serialize(self) -> Dict[str, Optional[str]]:
        """
        Returns a dictionary of the key strings for storage.

        Returns:
            Dict[str, Optional[str]]: Dictionary with 'private' and 'public' keys.
        """
        return {
            "private": self.get_private_str(),
            "public": self.get_public_str()
        }

    def deserialize(self, key_data: Dict[str, str]) -> None:
        """
        Loads, validates, and sets the keys from a dictionary.

        Args:
            key_data: A dictionary containing 'private' and 'public' PEM strings.

        Raises:
            ValueError: If deserialization fails or keys do not match.
        """
        try:
            temp_priv = serialization.load_pem_private_key(
                key_data["private"].encode('utf-8'),
                password=None
            )
            temp_pub = serialization.load_pem_public_key(
                key_data["public"].encode('utf-8')
            )
            
            # Validate before committing to self attributes
            if self._validate(temp_priv, temp_pub):
                self.private_key = temp_priv
                self.public_key = temp_pub
                
        except Exception as e:
            raise ValueError(f"Failed to deserialize or validate keys: {e}")
