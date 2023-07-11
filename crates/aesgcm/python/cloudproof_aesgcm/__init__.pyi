class Aes256Gcm:
    """Use aes256gcm standard rust implementation"""

    @staticmethod
    def encrypt(
        key: bytes, nonce: bytes, plaintext: bytes, authenticated_data: bytes
    ) -> bytes:
        """AES256GCM encryption

        Args:
            key (bytes): symmetric key - 32 bytes
            plaintext (bytes): data to encrypt
            authenticated_data (bytes): authenticated data

        Returns:
            bytes
        """
    @staticmethod
    def decrypt(
        key: bytes, nonce: bytes, ciphertext: bytes, authenticated_data: bytes
    ) -> bytes:
        """AES256GCM decryption

        Args:
            key (bytes): symmetric key - 32 bytes
            ciphertext (bytes): data to encrypt
            authenticated_data (bytes): authenticated data

        Returns:
            bytes
        """
