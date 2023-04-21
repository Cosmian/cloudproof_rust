# -*- coding: utf-8 -*-
import unittest

from cloudproof_anonymization import Hasher, NoiseGenerator


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


class TestNoiseGen(unittest.TestCase):
    def test_gaussian_float(self) -> None:
        gaussian_noise_generator = NoiseGenerator.new_with_parameters(
            'Gaussian', 0.0, 2.0
        )
        noisy_data = gaussian_noise_generator.apply_on_float(40.0)
        self.assertGreaterEqual(noisy_data, 30.0)
        self.assertLessEqual(noisy_data, 50.0)

        gaussian_noise_generator = NoiseGenerator.new_with_bounds(
            'Gaussian', -10.0, 10.0
        )
        noisy_data = gaussian_noise_generator.apply_on_float(40.0)
        self.assertGreaterEqual(noisy_data, 30.0)
        self.assertLessEqual(noisy_data, 50.0)

        with self.assertRaises(Exception):
            gaussian_noise_generator = NoiseGenerator.new_with_parameters(
                'Gaussian', 0.0, -1.0
            )

        with self.assertRaises(Exception):
            gaussian_noise_generator = NoiseGenerator.new_with_bounds(
                'Gaussian', 1.0, 0.0
            )


if __name__ == '__main__':
    unittest.main()
