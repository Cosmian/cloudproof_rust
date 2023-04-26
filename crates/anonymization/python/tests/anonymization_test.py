# -*- coding: utf-8 -*-
import unittest
from datetime import datetime

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

        hasher = Hasher('Argon2', b'example salt')
        res = hasher.apply(b'low entropy data')
        self.assertEqual(res, 'JXiQyIYJAIMZoDKhA/BOKTo+142aTkDvtITEI7NXDEM=')


class TestNoiseGen(unittest.TestCase):
    def test_gaussian_float(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters('Gaussian', 0.0, 1.0)
        noisy_data = noise_generator.apply_on_float(40.0)
        self.assertGreaterEqual(noisy_data, 30.0)
        self.assertLessEqual(noisy_data, 50.0)

        noise_generator = NoiseGenerator.new_with_bounds('Gaussian', -5.0, 5.0)
        noisy_data = noise_generator.apply_on_float(40.0)
        self.assertGreaterEqual(noisy_data, 30.0)
        self.assertLessEqual(noisy_data, 50.0)

        with self.assertRaises(Exception):
            noise_generator = NoiseGenerator.new_with_parameters('Gaussian', 0.0, -1.0)

        with self.assertRaises(Exception):
            noise_generator = NoiseGenerator.new_with_bounds('Gaussian', 1.0, 0.0)

    def test_laplacian_float(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters('Laplace', 0.0, 1.0)
        noisy_data = noise_generator.apply_on_float(40.0)
        self.assertGreaterEqual(noisy_data, 30.0)
        self.assertLessEqual(noisy_data, 50.0)

        noise_generator = NoiseGenerator.new_with_bounds('Laplace', -10.0, 10.0)
        noisy_data = noise_generator.apply_on_float(40.0)
        self.assertGreaterEqual(noisy_data, 30.0)
        self.assertLessEqual(noisy_data, 50.0)

    def test_uniform_float(self) -> None:
        noise_generator = NoiseGenerator.new_with_bounds('Uniform', -10.0, 10.0)
        noisy_data = noise_generator.apply_on_float(40.0)
        self.assertGreaterEqual(noisy_data, 30.0)
        self.assertLessEqual(noisy_data, 50.0)

        with self.assertRaises(Exception):
            noise_generator = NoiseGenerator.new_with_parameters('Uniform', 1.0, 0.0)

    def test_gaussian_int(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters('Gaussian', 0.0, 1.0)
        noisy_data = noise_generator.apply_on_int(40)
        self.assertGreaterEqual(noisy_data, 30)
        self.assertLessEqual(noisy_data, 50)

        noise_generator = NoiseGenerator.new_with_bounds('Gaussian', -5, 5)
        noisy_data = noise_generator.apply_on_int(40)
        self.assertGreaterEqual(noisy_data, 30)
        self.assertLessEqual(noisy_data, 50)

    def test_laplacian_int(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters('Laplace', 0, 1)
        noisy_data = noise_generator.apply_on_int(40)
        self.assertGreaterEqual(noisy_data, 30)
        self.assertLessEqual(noisy_data, 50)

        noise_generator = NoiseGenerator.new_with_bounds('Laplace', -10, 10)
        noisy_data = noise_generator.apply_on_int(40)
        self.assertGreaterEqual(noisy_data, 30)
        self.assertLessEqual(noisy_data, 50)

    def test_uniform_int(self) -> None:
        noise_generator = NoiseGenerator.new_with_bounds('Uniform', -10, 10)
        noisy_data = noise_generator.apply_on_int(40)
        self.assertGreaterEqual(noisy_data, 30)
        self.assertLessEqual(noisy_data, 50)

    def test_gaussian_date(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters(
            'Gaussian', 0.0, 2.0 * 3600
        )
        noisy_date_str = noise_generator.apply_on_date('2023-04-07T12:34:56Z')

        dt = datetime.fromisoformat(noisy_date_str)
        self.assertEqual(dt.day, 7)
        self.assertEqual(dt.month, 4)
        self.assertEqual(dt.year, 2023)

    def test_laplacian_date(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters('Laplace', 0, 2.0 * 3600)
        noisy_date_str = noise_generator.apply_on_date('2023-04-07T12:34:56Z')

        dt = datetime.fromisoformat(noisy_date_str)
        self.assertEqual(dt.day, 7)
        self.assertEqual(dt.month, 4)
        self.assertEqual(dt.year, 2023)

    def test_uniform_date(self) -> None:
        noise_generator = NoiseGenerator.new_with_bounds(
            'Uniform', -10 * 3600, 10 * 3600
        )
        noisy_date_str = noise_generator.apply_on_date('2023-04-07T12:34:56Z')

        dt = datetime.fromisoformat(noisy_date_str)
        self.assertEqual(dt.day, 7)
        self.assertEqual(dt.month, 4)
        self.assertEqual(dt.year, 2023)

    def test_correlated_noise(self) -> None:
        noise_generator = NoiseGenerator.new_with_parameters('Gaussian', 10.0, 2.0)
        values = [1.0, 1.0, 1.0]
        factors = [1.0, 2.0, 4.0]

        res = noise_generator.apply_correlated_noise(values, factors)
        self.assertEqual(
            (res[0] - values[0]) / factors[0], (res[1] - values[1]) / factors[1]
        )
        self.assertEqual(
            (res[0] - values[0]) / factors[0], (res[2] - values[2]) / factors[2]
        )


if __name__ == '__main__':
    unittest.main()
