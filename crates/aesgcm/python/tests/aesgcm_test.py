# -*- coding: utf-8 -*-
import os
import unittest

from cloudproof_aesgcm import (
    AesGcm,
)

KEY = os.urandom(32)
NONCE = os.urandom(12)


class TestEncryption(unittest.TestCase):
    def test_encrypt(self) -> None:
        """
        AESGCM test encrypt decrypt
        """
        plaintext = os.urandom(1024)
        aesgcm = AesGcm(KEY, NONCE)
        ciphertext = aesgcm.encrypt(plaintext)
        cleartext = aesgcm.decrypt(ciphertext)
        print(type(plaintext))
        print(type(cleartext))
        assert plaintext == bytes(cleartext)


if __name__ == '__main__':
    unittest.main()
