# -*- coding: utf-8 -*-
import os
import unittest

from cloudproof_aesgcm import (
    AesGcm,
)

KEY = os.urandom(32)
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
        ciphertext = AesGcm.encrypt(KEY, plaintext, AUTHENTICATED_DATA)
        cleartext = AesGcm.decrypt(KEY, ciphertext, AUTHENTICATED_DATA)
        print(type(plaintext))
        print(type(cleartext))
        assert plaintext == bytes(cleartext)


if __name__ == '__main__':
    unittest.main()
