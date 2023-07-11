# -*- coding: utf-8 -*-
import os
import unittest

from cloudproof_aesgcm import (
    Aes256Gcm,
)

KEY = os.urandom(32)
NONCE = os.urandom(12)
AUTHENTICATED_DATA = os.urandom(1024)


class TestEncryption(unittest.TestCase):
    """
    Test on AES256GCM encryption and decryption
    """

    def test_encrypt(self) -> None:
        """
        AESGCM test encrypt decrypt
        """
        plaintext = os.urandom(1024)
        ciphertext = Aes256Gcm.encrypt(KEY, NONCE, plaintext, AUTHENTICATED_DATA)
        cleartext = Aes256Gcm.decrypt(KEY, NONCE, ciphertext, AUTHENTICATED_DATA)
        print(type(plaintext))
        print(type(cleartext))
        assert plaintext == bytes(cleartext)


if __name__ == '__main__':
    unittest.main()
