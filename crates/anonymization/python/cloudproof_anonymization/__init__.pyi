from typing import List, Optional

class Hasher:
    def __init__(self, hasher_method: str, salt: Optional[bytes] = None) -> None:
        """
        Creates a new `Hasher` instance using the specified hash method and an optional salt.

        Args:
            method (str): The hash method to use. This can be one of the following:
                - `SHA2`: Fast and secure, but vulnerable to brute-force attacks.
                - `SHA3`: Secure and resistant to brute-force attacks, but slower than SHA-256 and not as widely supported.
                - `Argon2`: Highly resistant to brute-force attacks, but can be slower than other hash functions and may require more memory.
            salt (bytes, optional): An optional salt to use. Required with Argon2.

        """
    def apply(self, data: bytes) -> str:
        """
        Applies the chosen hash method to the input data

        Args:
            data (bytes): A byte slice representing the input data to be hashed.

        Returns:
            str: The base64-encoded hash string."""

class NoiseGenerator:
    @staticmethod
    def new_with_parameters(
        method_name: str, mean: float, std_dev: float
    ) -> NoiseGenerator:
        """
        Instantiate a `NoiseGenerator` using mean and standard deviation.

        Args:
            method_name (str): The noise distribution to use ("Gaussian" or "Laplace").
            mean (float): Mean of the noise distribution.
            std_dev (float): The standard deviation of the noise distribution."""
    @staticmethod
    def new_with_bounds(
        method_name: str, min_bound: float, max_bound: float
    ) -> NoiseGenerator:
        """
        Instantiate a `NoiseGenerator` with bound constraints.

        Args:
            method_name (str): The noise distribution to use ("Uniform", "Gaussian", or "Laplace").
            min_bound (float): The lower bound of the range of possible generated noise values.
            max_bound (float): The upper bound of the range of possible generated noise values.

        Returns:
            NoiseGenerator: A new `NoiseGenerator` instance with the specified noise distribution and bound constraints.
        """
    def apply_on_float(self, data: float) -> float:
        """
        Adds noise generated from a chosen distribution to the input data.

        Args:
            data (float): A single float value to which noise will be added.

        Returns:
            float: Original data with added noise.
        """
    def apply_correlated_noise(
        self, data: List[float], factors: List[float]
    ) -> List[float]:
        """
        Applies correlated noise to a vector of data, based on precomputed
        factors. The noise is sampled once and then applied to each data
        point, scaled by a corresponding factor.

        Args:
            data (List[float]): Data to add noise to.
            factors (List[float]): Factors to scale the noise with, one for each data point.

        Returns:
            List[float]: A vector containing the original data with added noise.
        """
    def apply_on_int(self, data: int) -> int:
        """
        Adds noise generated from a chosen distribution to the input data.

        Arguments:
        - data: An integer value to which noise will be added.

        Returns:
        - Original data with added noise
        """
    def apply_on_date(self, date: str) -> str:
        """
        Applies the selected noise method on a given date string.

        Arguments:
        - date_str: A date string in the RFC3339 format.

        Returns:
        - The resulting noisy date string
        """

class WordMasker:
    def __init__(self, words_to_block: List[str]) -> None:
        """
        Creates a new WordMasker instance.

        Args:
        - words_to_block: A list of strings containing the words to be masked in the text.
        """
        self.word_list = set(word.lower() for word in words_to_block)
    def apply(self, data: str) -> str:
        """
        Masks the specified words in the given text.

        Args:
        - data: A string containing the text to be masked.

        Returns:
        - Text without the sensitive words.
        """

class WordTokenizer:
    def __init__(self, words_to_block: List[str]) -> None:
        """
        Creates a new instance of WordTokenizer.

        Args:
            words_to_block: A list of strings representing the words to be replaced with tokens.
        """
    def apply(self, data: str) -> str:
        """
        Remove sensitive words from a text by replacing them with tokens.

        Args:
            data: A string representing the input text.

        Returns:
            A string containing tokens in place of sensitive words.
        """

class WordPatternMasker:
    def __init__(self, pattern_regex: str, replace_str: str) -> None:
        """
        Creates a new instance of `WordPatternMasker` with the provided pattern
        regex and replace string.

        Args:
            pattern_regex: The pattern regex to search for.
            replace_str: The string to replace the matched patterns.
        """
    def apply(self, data: str) -> str:
        """
        Applies the pattern mask to the provided data.

        Args:
            data: The data to be masked.

        Returns:
            Text with the matched pattern replaced.
        """

class NumberAggregator:
    """
    A class to round numbers to a desired power of ten.
    """

    def __init__(self, power_of_ten_exponent: int) -> None:
        """
        Initializes a new instance of `NumberAggregator`.

        Args:
            power_of_ten_exponent (int): The power of ten to round the numbers to.
        """
    def apply_on_float(self, data: float) -> str:
        """
        Rounds a floating point number to the desired power of ten.

        Args:
            data (float): The floating point number to round.

        Returns:
        - A string representation of the rounded number.
        """
    def apply_on_int(self, data: int) -> str:
        """
        Rounds an integer to the desired power of ten.

        Args:
            data (int): The integer to round.

        Returns:
            A string representation of the rounded number.
        """

class DateAggregator:
    """
    A class for rounding dates based on the specified time unit.
    """

    def __init__(self, time_unit: str) -> None:
        """
        Creates a new instance of `DateAggregator` with the provided time unit.

        Args:
        - time_unit (str): the unit of time to round the date to.
        """
    def apply_on_date(self, date_str: str) -> str:
        """
        Applies the date rounding to the provided date string based on the unit of time.

        Args:
        - date_str (str): A string representing the date to be rounded.

        Returns:
        - The rounded date in RFC 3339.
        """
