class Alphabet:
    """
    The `Alphabet` class brings Format Preserving Encryption (FPE) functions
    like encryption and decryption on a parametrize alphabet
    """

    def __init__(self, alphabet_id: str):
        """
        Initialize the FormatPreservingEncryption instance with a given
        alphabet type.

        Args:
            alphabet_type (str): A string indicating the type of alphabet to be used
                for the encryption. Currently, only the following options are supported:
                - "numeric",
                - "hexa_decimal",
                - "alpha_lower",
                - "alpha_upper",
                - "alpha",
                - "alpha_numeric",
                - "utf",
                - "chinese",
                - "latin1sup",
                - "latin1sup_alphanum".
        """
    def encrypt(self, key: bytes, tweak: bytes, plaintext: str) -> str:
        """
        Encrypts a plaintext using the specified key and tweak.

        Args:
            key (bytes): A bytes object containing the key to be used for the encryption.
            tweak (bytes): A bytes object containing the tweak to be used for the encryption.
            plaintext (str): A string containing the plaintext to be encrypted.

        Returns:
            str: A string containing the ciphertext produced by encrypting the plaintext
                using the specified key and tweak.
        """
    def decrypt(self, key: bytes, tweak: bytes, ciphertext: str) -> str:
        """
        Decrypts a ciphertext using the specified key and tweak.

        Args:
            key (bytes): A bytes object containing the key to be used for the decryption.
            tweak (bytes): A bytes object containing the tweak to be used for the decryption.
            ciphertext (str): A string containing the ciphertext to be decrypted.

        Returns:
            str: A string containing the plaintext produced by decrypting the ciphertext
                using the specified key and tweak.
        """
    def extend_with(self, additional_characters: str) -> None:
        """
        Extends the current alphabet with additional characters.

        Args:
            additional_characters (str): A string containing the additional characters
                to add to the alphabet.

        Returns:
            None: This method does not return anything.
        """

class Integer:
    """
    A class that represents an integer in a finite field and provides
    methods for encryption and decryption using the FPE (Format Preserving
    Encryption) algorithm.

    Parameters:
        radix (int): The radix used for the integer.
        digits (int): The number of digits used for the integer.
    """

    def __init__(self, radix: int, digits: int):
        """
        Initializes a new Integer object with the given radix and number of digits.

        Args:
            radix (int): The radix used for the integer.
            digits (int): The number of digits used for the integer.
        """
    def encrypt(self, key: bytes, tweak: bytes, plaintext: int) -> int:
        """
        Encrypts a plaintext integer using the FPE algorithm with the given key and tweak.
        Args:
            key (bytes): The key used for encryption.
            tweak (bytes): The tweak used for encryption.
            plaintext (int): The integer to be encrypted.
        Returns:
            int: The encrypted integer.
        """
    def decrypt(self, key: bytes, tweak: bytes, ciphertext: int) -> int:
        """
        Decrypts a ciphertext integer using the FPE algorithm with the given key and tweak.
        Args:
            key (bytes): The key used for decryption.
            tweak (bytes): The tweak used for decryption.
            ciphertext (int): The integer to be decrypted.
        Returns:
            int: The decrypted integer.
        """
    def encrypt_big(
        self,
        key: bytes,
        tweak: bytes,
        plaintext: str,
    ) -> str:
        """
        Encrypts a plaintext string using the FPE algorithm with the given key and tweak.
        The plaintext string is first converted to a big integer using the radix of the Integer instance.

        Args:
            key (bytes): The key used for encryption.
            tweak (bytes): The tweak used for encryption.
            plaintext (str): The string to be encrypted.

        Returns:
            str: The encrypted string.
        """
    def decrypt_big(self, key: bytes, tweak: bytes, ciphertext: str) -> str:
        """
        Decrypts a ciphertext string using the FPE algorithm with the given key and tweak.
        The ciphertext string is first converted to a big integer using the radix of the Integer instance.

        Args:
            key (bytes): The key used for decryption.
            tweak (bytes): The tweak used for decryption.
            ciphertext (str): The string to be decrypted.

        Returns:
            str: The decrypted string.
        """

class Float:
    """
    A class representing a floating point number and providing methods for
    encrypting and decrypting floating point numbers using a specified key and tweak.
    """

    def __init__(self):
        """
        Initializes a new Float object.
        """
    def encrypt(self, key: bytes, tweak: bytes, plaintext: float) -> float:
        """
        Encrypts the given plaintext floating point number using the specified key and tweak,
        and returns the ciphertext.

        Args:
            key (bytes): A bytes object representing the encryption key.
            tweak (bytes): A bytes object representing the encryption tweak.
            plaintext (float): A float representing the plaintext floating point number to encrypt.

        Returns:
            float: A float representing the ciphertext value.
        """
    def decrypt(self, key: bytes, tweak: bytes, ciphertext: float) -> float:
        """
        Decrypts the given ciphertext floating point number using the specified key and tweak,
        and returns the plaintext.

        Args:
            key (bytes): A bytes object representing the encryption key.
            tweak (bytes): A bytes object representing the encryption tweak.
            ciphertext (float): A float representing the ciphertext value to decrypt.

        Returns:
            float: the plaintext floating point number.
        """
