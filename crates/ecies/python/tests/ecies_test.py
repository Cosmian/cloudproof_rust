# -*- coding: utf-8 -*-
import os
import unittest

from cloudproof_ecies import (
    Ecies,
)

KEY = os.urandom(32)
AUTHENTICATION_DATA = os.urandom(1024)


class TestEncryption(unittest.TestCase):
    def test_encrypt(self) -> None:
        """
        ECIES test encrypt decrypt
        """
        plaintext = os.urandom(1024)
        key_pair = Ecies.generate_key_pair()
        ciphertext = Ecies.encrypt(plaintext, key_pair[0], AUTHENTICATION_DATA)
        cleartext = Ecies.decrypt(ciphertext, key_pair[1], AUTHENTICATION_DATA)
        assert plaintext == bytes(cleartext)


if __name__ == '__main__':
    unittest.main()
