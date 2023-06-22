# -*- coding: utf-8 -*-
import os
import unittest

from cloudproof_ecies import (
    Ecies,
)

KEY = os.urandom(32)
NONCE = os.urandom(12)


class TestEncryption(unittest.TestCase):
    def test_encrypt(self) -> None:
        """
        ECIES test encrypt decrypt
        """
        plaintext = os.urandom(1024)
        key_pair = Ecies.generate_key_pair()
        ciphertext = Ecies.encrypt(plaintext, key_pair[0])
        cleartext = Ecies.decrypt(ciphertext, key_pair[1])
        assert plaintext == bytes(cleartext)


if __name__ == '__main__':
    unittest.main()
