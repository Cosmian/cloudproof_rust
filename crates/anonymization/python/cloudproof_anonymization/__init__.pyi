from typing import List, Optional

class Hasher:
    """
    A class to apply different hash methods such as `SHA2`, `SHA3`, or `Argon2`
    """

    def __init__(self, hasher_method: str, salt: Optional[bytes] = None) -> None:
        """
        Creates a new `Hasher` instance using the specified hash method and an optional salt.

        Args:
            method (str): The hash method to use. This can be one of the following:
                - `SHA2`  : Fast but vulnerable to brute-force attacks.
                - `SHA3`  : Resistant to brute-force attacks, but slower than SHA-256 and not as widely supported.
                - `Argon2`: Highly resistant to brute-force attacks, but can be slower than other hash functions and may require more memory.
            salt (bytes, optional): An optional salt to use. Required with Argon2.
        """
    def apply_str(self, data: str) -> str:
        """
        Applies the chosen hash method to the input data

        Args:
            data (str): Input string to be hashed.

        Returns:
            str: The base64-encoded hash string.
        """
    def apply_bytes(self, data: bytes) -> bytes:
        """
        Applies the chosen hash method to the input data

        Args:
            data (bytes): Input data to be hashed.

        Returns:
            bytes: The hash bytes.
        """

class NoiseGenerator:
    """
    A class for adding noise to data using various distributions such as `Uniform`, `Gaussian`, or `Laplace`.
    """

    @staticmethod
    def new_with_parameters(
        method_name: str, mean: float, std_dev: float
    ) -> NoiseGenerator:
        """
        Instantiate a `NoiseGenerator` using mean and standard deviation.

        Args:
            method_name (str): The noise distribution to use ("Gaussian" or "Laplace").
            mean (float): Mean of the noise distribution.
            std_dev (float): The standard deviation of the noise distribution.
        """
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
        """
    def apply_on_float(self, data: float) -> float:
        """
        Adds noise generated from a chosen distribution to the input data.

        Args:
            data (float): A single float value to which noise will be added.

        Returns:
            float: Original data with added noise.
        """
    def apply_correlated_noise_on_floats(
        self, data: List[float], factors: List[float]
    ) -> List[float]:
        """
        Applies correlated noise to a vector of data.
        The noise is sampled once and then applied to each data point, scaled by a corresponding factor.

        Args:
            data (List[float]): Data to add noise to.
            factors (List[float]): Factors to scale the noise with, one for each data point.

        Returns:
            List[float]: A vector containing the original data with added noise.
        """
    def apply_on_int(self, data: int) -> int:
        """
        Adds noise generated from a chosen distribution to the input data.

        Args:
            data (int): An integer value to which noise will be added.

        Returns:
            int: Original data with added noise
        """
    def apply_correlated_noise_on_ints(
        self, data: List[int], factors: List[float]
    ) -> List[int]:
        """
        Applies correlated noise to a vector of data.
        The noise is sampled once and then applied to each data point, scaled by a corresponding factor.

        Args:
            data (List[int]): Data to add noise to.
            factors (List[float]): Factors to scale the noise with, one for each data point.

        Returns:
            List[int]: A vector containing the original data with added noise.
        """
    def apply_on_date(self, date: str) -> str:
        """
        Applies the selected noise method on a given date string.

        Args:
            date_str (str): A date string in the RFC3339 format.

        Returns:
            str: The resulting noisy date string
        """
    def apply_correlated_noise_on_dates(
        self, data: List[str], factors: List[float]
    ) -> List[str]:
        """
        Applies correlated noise to a vector of data.
        The noise is sampled once and then applied to each data point, scaled by a corresponding factor.

        Args:
            data (List[str]): Data to add noise to.
            factors (List[float]): Factors to scale the noise with, one for each data point.

        Returns:
            List[str]: A vector containing the original data with added noise.
        """

class WordMasker:
    """
    A class to mask a list of words in a text.
    """

    def __init__(self, words_list: List[str]) -> None:
        """
        Creates a new WordMasker instance.

        Args:
            words_to_block (List[str]): A list of strings containing the words to be masked in the text.
        """
    def apply(self, data: str) -> str:
        """
        Masks the specified words in the given text.

        Args:
            data (str): A string containing the text to be masked.

        Returns:
            str: Text without the sensitive words.
        """

class WordTokenizer:
    """
    A class to tokenize a list of words in a text.
    """

    def __init__(self, words_list: List[str]) -> None:
        """
        Creates a new instance of WordTokenizer.

        Args:
            words_list (List[str]): A list of strings representing the words to be replaced with tokens.
        """
    def apply(self, data: str) -> str:
        """
        Remove sensitive words from a text by replacing them with tokens.

        Args:
            data (str): A string representing the input text.

        Returns:
            str: A string containing tokens in place of sensitive words.
        """

class WordPatternMasker:
    """
    A class to replace pattern regex with a replacement string.
    """

    def __init__(self, pattern: str, replace: str) -> None:
        """
        Creates a new instance of `WordPatternMasker` with the provided pattern
        regex and replace string.

        Args:
            pattern (str): The pattern regex to search for.
            replace (str): The string to replace the matched patterns.
        """
    def apply(self, data: str) -> str:
        """
        Applies the pattern mask to the provided data.

        Args:
            data (str): The data to be masked.

        Returns:
            str: Text with the matched pattern replaced.
        """

class NumberAggregator:
    """
    A class to round numbers to a desired power of ten.
    """

    def __init__(self, power_of_ten: int) -> None:
        """
        Initializes a new instance of `NumberAggregator`.

        Args:
            power_of_ten (int): The power of ten to round the numbers to.
        """
    def apply_on_float(self, data: float) -> str:
        """
        Rounds a floating point number to the desired power of ten.

        Args:
            data (float): The floating point number to round.

        Returns:
            str: A string representation of the rounded number.
        """
    def apply_on_int(self, data: int) -> str:
        """
        Rounds an integer to the desired power of ten.

        Args:
            data (int): The integer to round.

        Returns:
            str: A string representation of the rounded number.
        """

class DateAggregator:
    """
    A class for rounding dates based on the specified time unit.
    """

    def __init__(self, time_unit: str) -> None:
        """
        Creates a new instance of `DateAggregator` with the provided time unit.

        Args:
            time_unit (str): the unit of time to round the date to.
        """
    def apply_on_date(self, date_str: str) -> str:
        """
        Applies the date rounding to the provided date string based on the unit of time.

        Args:
            date_str (str): A string representing the date to be rounded.

        Returns:
            str: The rounded date in RFC 3339.
        """

class NumberScaler:
    """
    A class to scale and translate floating points or integer values.
    """

    def __init__(self, mean: float, std_dev: float, scale: float, translation: float):
        """
        Initializes a new instance of `NumberScaler`.

        Args:
            mean (float): The mean of the data distribution.
            std_dev (float): The standard deviation of the data distribution.
            scale (float): The scaling factor.
            translation (float): The translation factor.
        """
    def apply_on_float(self, data: float) -> float:
        """
        Applies the scaling and translation on a floating-point number.

        Args:
            data (float): A floating-point number to be scaled.

        Returns:
            float: The scaled value.
        """
    def apply_on_int(self, data: int) -> int:
        """
        Applies the scaling and translation on an integer.

        Args:
            data (int): An integer to be scaled.

        Returns:
            int: The scaled value as an integer.
        """
