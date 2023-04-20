# -*- coding: utf-8 -*-
import unittest

from cloudproof_anonymization import Hasher


class TestHasher(unittest.TestCase):
    def test_sha2(self) -> None:
        hasher = Hasher('SHA2')
        res = hasher.apply(b'test sha2')
        self.assertEqual(res, 'Px0txVYqBePXWF5K4xFn0Pa2mhnYA/jfsLtpIF70vJ8=')

        hasher = Hasher('SHA2', b'example salt')
        res = hasher.apply(b'test sha2')
        self.assertEqual(res, 'd32KiG7kpZoaU2/Rqa+gbtaxDIKRA32nIxwhOXCaH1o=')

    def test_sha3(self) -> None:
        hasher = Hasher('SHA3')
        res = hasher.apply(b'test sha3')
        self.assertEqual(res, 'b8rRtRqnSFs8s12jsKSXHFcLf5MeHx8g6m4tvZq04/I=')

        hasher = Hasher('SHA3', b'example salt')
        res = hasher.apply(b'test sha3')
        self.assertEqual(res, 'UBtIW7mX+cfdh3T3aPl/l465dBUbgKKZvMjZNNjwQ50=')

    def test_argon2(self) -> None:
        with self.assertRaises(Exception):
            # should fail without salt
            hasher = Hasher('Argon2')
            res = hasher.apply(b'low entropy data')

        hasher = Hasher('Argon2', b'example salt')
        res = hasher.apply(b'low entropy data')
        self.assertEqual(res, 'JXiQyIYJAIMZoDKhA/BOKTo+142aTkDvtITEI7NXDEM=')


if __name__ == '__main__':
    unittest.main()
