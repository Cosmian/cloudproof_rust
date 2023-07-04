class AesGcm:
    """Use aes256gcm standard rust implementation

    Args:
        key (bytes): symmetric key - 32 bytes
        nonce (bytes): AESGCM nonce - 12 bytes
    """

    def __init__(self, key: bytes, nonce: bytes):
        """
        Initialize the AESGCM cipher

        Args:
            key (bytes): symmetric key - 32 bytes
            nonce (bytes): AESGCM nonce - 12 bytes
        """
    def encrypt(self, plaintext: bytes) -> bytes:
        """AES256GCM encryption

        Returns:
            bytes
        """
    def decrypt(self, ciphertext: bytes) -> bytes:
        """AES256GCM decryption

        Returns:
            bytes
        """
