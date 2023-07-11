# -*- coding: utf-8 -*-
import os
import unittest

from cloudproof_ecies import (
    EciesSalsaSealBox,
)

KEY = os.urandom(32)
AUTHENTICATION_DATA = os.urandom(1024)


class TestEncryption(unittest.TestCase):
    def test_encrypt(self) -> None:
        """
        ECIES test encrypt decrypt
        """
        plaintext = os.urandom(1024)
        key_pair = EciesSalsaSealBox.generate_key_pair()
        ciphertext = EciesSalsaSealBox.encrypt(
            plaintext, key_pair[0], AUTHENTICATION_DATA
        )
        cleartext = EciesSalsaSealBox.decrypt(
            ciphertext, key_pair[1], AUTHENTICATION_DATA
        )
        assert plaintext == bytes(cleartext)


if __name__ == '__main__':
    unittest.main()
