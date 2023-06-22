from typing import Tuple

class Ecies:
    """Use Ecies scheme"""

    def generate_key_pair() -> Tuple[bytes, bytes]:
        """
        Generate ECIES key pair

        """
    def encrypt(plaintext: bytes, public_key_bytes: bytes) -> bytes:
        """ECIES encryption

        Returns:
            bytes
        """
    def decrypt(ciphertext: bytes, private_key_bytes: bytes) -> bytes:
        """ECIES decryption

        Returns:
            bytes
        """
