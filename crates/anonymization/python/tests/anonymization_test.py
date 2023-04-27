# -*- coding: utf-8 -*-
import unittest
from datetime import datetime

from cloudproof_anonymization import (
    DateAggregator,
    Hasher,
    NoiseGenerator,
    NumberAggregator,
    WordMasker,
    WordPatternMasker,
    WordTokenizer,
)
from dateutil.parser import parse as parse_date
from dateutil.tz import tzutc


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


class TestWordMasking(unittest.TestCase):
    def test_word_masker(self) -> None:
        word_masker = WordMasker(['quick', 'brown', 'dog'])
        data = 'The Quick! brown fox, Jumps over the lazy dog.'
        expected_result = 'The XXXX! XXXX fox, Jumps over the lazy XXXX.'
        self.assertEqual(expected_result, word_masker.apply(data))

    def test_word_tokenizer(self) -> None:
        word_tokenizer = WordTokenizer(['password', 'secret'])
        text = 'My password is secret'
        masked_text = word_tokenizer.apply(text)
        self.assertNotIn('password', masked_text)
        self.assertNotIn('secret', masked_text)

    def test_word_pattern_masker(self) -> None:
        pattern = r'\b\d{4}-\d{2}-\d{2}\b'
        replace_str = 'DATE'
        masker = WordPatternMasker(pattern, replace_str)

        # Test case where pattern is present
        data = 'On 2022-04-01, the company announced its plans for expansion.'
        expected_output = 'On DATE, the company announced its plans for expansion.'
        self.assertEqual(masker.apply(data), expected_output)

        # Test case where pattern is not present
        data = 'The quick brown fox jumps over the lazy dog.'
        expected_output = 'The quick brown fox jumps over the lazy dog.'
        self.assertEqual(masker.apply(data), expected_output)

        # Invalid regex
        with self.assertRaises(Exception):
            WordPatternMasker('(', 'XXX')


class TestNumberAnonymize(unittest.TestCase):
    def test_number_aggregator_with_invalid_exponent(self) -> None:
        with self.assertRaises(Exception):
            NumberAggregator(500)

    def test_number_aggregator_on_float(self):
        na = NumberAggregator(-2)
        self.assertEqual(na.apply_on_float(123.456789), '123.46')
        self.assertEqual(na.apply_on_float(0.001), '0.00')

        na = NumberAggregator(2)
        self.assertEqual(na.apply_on_float(123.456789), '100')

    def test_number_aggregator_on_int(self):
        na = NumberAggregator(3)
        self.assertEqual(na.apply_on_int(12345), '12000')
        self.assertEqual(na.apply_on_int(999), '1000')
        self.assertEqual(na.apply_on_int(499), '0')

    def test_date_aggregator(self):
        # Test rounding to the nearest minute
        aggregator = DateAggregator('Minute')
        rounded_date_str = aggregator.apply_on_date('2023-04-27T16:23:45Z')
        rounded_date = parse_date(rounded_date_str)
        expected_date = datetime(2023, 4, 27, 16, 23, 0, tzinfo=tzutc())
        self.assertEqual(rounded_date, expected_date)

        # Test rounding to the nearest hour
        aggregator = DateAggregator('Hour')
        rounded_date_str = aggregator.apply_on_date('2023-04-27T16:23:45Z')
        rounded_date = parse_date(rounded_date_str)
        expected_date = datetime(2023, 4, 27, 16, 0, 0, tzinfo=tzutc())
        self.assertEqual(rounded_date, expected_date)

        # Test rounding to the nearest day
        aggregator = DateAggregator('Day')
        rounded_date_str = aggregator.apply_on_date('2023-04-27T16:23:45Z')
        rounded_date = parse_date(rounded_date_str)
        expected_date = datetime(2023, 4, 27, 0, 0, 0, tzinfo=tzutc())
        self.assertEqual(rounded_date, expected_date)

        # Test rounding to the nearest month
        aggregator = DateAggregator('Month')
        rounded_date_str = aggregator.apply_on_date('2023-04-27T16:23:45Z')
        rounded_date = parse_date(rounded_date_str)
        expected_date = datetime(2023, 4, 1, 0, 0, 0, tzinfo=tzutc())
        self.assertEqual(rounded_date, expected_date)

        # Test rounding to the nearest year
        aggregator = DateAggregator('Year')
        rounded_date_str = aggregator.apply_on_date('2023-04-27T16:23:45Z')
        rounded_date = parse_date(rounded_date_str)
        expected_date = datetime(2023, 1, 1, 0, 0, 0, tzinfo=tzutc())
        self.assertEqual(rounded_date, expected_date)

        aggregator = DateAggregator('InvalidUnit')
        with self.assertRaises(Exception):
            aggregator.apply_on_date('2023-04-27T16:23:45Z')


if __name__ == '__main__':
    unittest.main()
