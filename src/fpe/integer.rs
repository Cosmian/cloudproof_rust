use super::Alphabet;
use crate::error::AnoError;
use num_bigint::BigUint;
use num_traits::{Num, One, ToPrimitive};

pub struct Integer {
    pub(crate) radix: u32,
    pub(crate) digits: usize,
    pub(crate) max_value: BigUint,
    pub(crate) numeric_alphabet: Alphabet,
}

impl Integer {
    /// Creates a new instance of the `Integer` representation.
    /// It calculates the `max_value` as the number of `digits` raised to the power of `radix`.
    ///
    /// # Example
    /// ```
    /// use cosmian_anonymization::fpe::Integer;
    /// use num_bigint::BigUint;
    ///
    /// let number = Integer::instantiate(8, 7).unwrap();
    /// assert_eq!(number.digits(), 7);
    /// assert_eq!(number.max_value(), BigUint::from(2097151_u64));
    /// ```
    ///
    /// # Arguments
    /// `radix` - The base of the number representation. Must be between 2 and 16 inclusive.
    /// `digits` - The number of digits in the representation.
    ///
    /// # Returns
    /// A new instance of `Integer` representation.
    ///
    /// # Errors
    /// If the `radix` is not between 2 and 16 inclusive or the calculation of the maximum value fails.
    pub fn instantiate(radix: u32, digits: usize) -> Result<Self, AnoError> {
        let min_digits = match radix {
            2 => 20,
            3 => 13,
            4 => 10,
            5 => 9,
            6 => 8,
            7 => 8,
            8 => 7,
            9 => 7,
            10 => 6,
            11 => 6,
            12 => 6,
            13 => 6,
            14 => 6,
            15 => 6,
            16 => 5,
            _ => {
                return Err(AnoError::FPE(format!(
                    "Radix must be between 2 and 16 inclusive, got {}",
                    radix
                )));
            }
        };

        if digits < min_digits {
            return Err(AnoError::FPE(format!(
                "Integer of digits must be at least {}, got {}",
                min_digits, digits
            )));
        }

        let max_value = BigUint::from(radix).pow(digits as u32) - BigUint::one();
        let alphabet = &"0123456789abcdef"[0..radix as usize];

        Ok(Integer {
            radix,
            digits,
            max_value,
            numeric_alphabet: Alphabet::try_from(alphabet)?,
        })
    }

    /// Encrypts a given `value` using the FPE method.
    /// The value must be lower or equal to the `max_value` of the Integer representation.
    ///
    /// # Example
    /// ```
    /// use cosmian_anonymization::fpe::Integer;
    ///
    /// let Integer = Integer::instantiate(10, 8).unwrap();
    /// let key = [0u8; 32];
    /// let tweak = b"tweak";
    ///
    /// let encrypted = Integer.encrypt(&key, tweak, 100).unwrap();
    /// assert_ne!(100, encrypted);
    ///
    /// let decrypted = Integer.decrypt(&key, tweak, encrypted).unwrap();
    /// assert_eq!(100, decrypted);
    /// ```
    ///
    /// # Arguments
    /// `value` - The big integer number to encrypt.
    /// `key` - Key used for encryption.
    /// `tweak` - Tweak
    ///
    /// # Returns
    /// The encrypted big integer number.
    pub fn encrypt(&self, key: &[u8; 32], tweak: &[u8], value: u64) -> Result<u64, AnoError> {
        let ciphertext = self.encrypt_big(key, tweak, &BigUint::from(value))?;
        ciphertext.to_u64().ok_or_else(|| {
            AnoError::FPE(format!(
                "failed converting the ciphertext value: {}, to an u64",
                ciphertext
            ))
        })
    }

    /// Encrypts a given `value` using the FPE method.
    /// The value must be lower or equal to the `max_value` of the Integer representation.
    ///
    /// # Example
    /// ```
    /// use cosmian_anonymization::fpe::Integer;
    /// use num_bigint::BigUint;
    ///
    /// let Integer = Integer::instantiate(16, 8).unwrap();
    /// let key = [0u8; 32];
    /// let tweak = b"tweak";
    ///
    /// let encrypted = Integer.encrypt_big(&key, tweak, &BigUint::from(0xa1_u64)).unwrap();
    /// assert_ne!(BigUint::from(0xa1_u64), encrypted);
    ///
    /// let decrypted = Integer.decrypt_big(&key, tweak, &encrypted).unwrap();
    /// assert_eq!(BigUint::from(0xa1_u64), decrypted);
    /// ```
    ///
    /// # Arguments
    /// `value` - The big integer number to encrypt.
    /// `key` - Key used for encryption.
    /// `tweak` - Tweak
    ///
    /// # Returns
    /// The encrypted big integer number.
    pub fn encrypt_big(
        &self,
        key: &[u8; 32],
        tweak: &[u8],
        big_value: &BigUint,
    ) -> Result<BigUint, AnoError> {
        if big_value > &self.max_value {
            return Err(AnoError::FPE(format!(
                "the value: {} must be lower or equal to {}",
                big_value, self.max_value
            )));
        }

        let digits = self.digits;
        let str_value = format!("{:0>digits$}", big_value.to_str_radix(self.radix));

        //encrypt
        let ciphertext = self.numeric_alphabet.encrypt(key, tweak, &str_value)?;
        let big_ciphertext = BigUint::from_str_radix(&ciphertext, self.radix)
            .map_err(|e| AnoError::FPE(format!("failed generating the ciphertext value {}", e)))?;
        Ok(big_ciphertext)
    }

    // Decrypts the ciphertext using the specified key and tweak and returns the plaintext as a u64.
    ///
    /// # Parameters
    ///
    /// - ciphertext: A u64 representing the encrypted value.
    /// - key: A &[u8; 32] representing the encryption key.
    /// - tweak: A &[u8] representing the tweak value.
    ///
    /// # Returns
    ///
    /// Returns the plaintext as a u64 on success, or an error if the decryption was not successful.
    ///
    /// # Errors
    ///
    /// This method returns an error in the following cases:
    /// - If the ciphertext is greater than the maximum value set for the Integer struct.
    /// - If the plaintext could not be generated from the ciphertext.
    /// - If the plaintext value could not be converted to a u64.
    ///
    /// # Example
    ///
    /// ```
    /// use cosmian_anonymization::fpe::Integer;
    /// use num_bigint::BigUint;
    ///
    /// let key = [0; 32];
    /// let tweak = [0];
    /// let number_radix = Integer::instantiate(16, 8).unwrap();
    /// let ciphertext = number_radix.encrypt_big(&key, &tweak, &BigUint::from(0xe2f3_u64)).unwrap();
    /// let plaintext = number_radix.decrypt_big(&key, &tweak, &ciphertext).unwrap();
    ///
    /// assert_eq!(BigUint::from(0xe2f3_u64), plaintext);
    /// `````
    pub fn decrypt(&self, key: &[u8; 32], tweak: &[u8], ciphertext: u64) -> Result<u64, AnoError> {
        let plaintext = self.decrypt_big(key, tweak, &BigUint::from(ciphertext))?;
        plaintext.to_u64().ok_or_else(|| {
            AnoError::FPE(format!(
                "failed converting the plaintext value: {}, to an u64",
                plaintext
            ))
        })
    }

    // Decrypts the ciphertext using the specified key and tweak and returns the plaintext as a BigUint.
    ///
    /// # Parameters
    ///
    /// - ciphertext: A BigUint representing the encrypted value.
    /// - key: A &[u8; 32] representing the encryption key.
    /// - tweak: A &[u8] representing the tweak value.
    ///
    /// # Returns
    ///
    /// Returns the plaintext as a BigUint on success, or an error if the decryption was not successful.
    ///
    /// # Errors
    ///
    /// This method returns an error in the following cases:
    /// - If the ciphertext is greater than the maximum value set for the Integer struct.
    /// - If the plaintext could not be generated from the ciphertext.
    /// - If the plaintext value could not be converted to a BigUint.
    ///
    /// # Example
    ///
    /// ```
    /// use cosmian_anonymization::fpe::Integer;
    /// use num_bigint::BigUint;
    ///
    /// let key = [0; 32];
    /// let tweak = [0];
    /// let number_radix = Integer::instantiate(10, 8).unwrap();
    /// let ciphertext = number_radix.encrypt_big(&key, &tweak, &BigUint::from(123456_u64)).unwrap();
    /// let plaintext = number_radix.decrypt_big(&key, &tweak, &ciphertext).unwrap();
    ///
    /// assert_eq!(BigUint::from(123456_u64), plaintext);
    /// `````
    pub fn decrypt_big(
        &self,
        key: &[u8; 32],
        tweak: &[u8],
        big_ciphertext: &BigUint,
    ) -> Result<BigUint, AnoError> {
        if big_ciphertext > &self.max_value {
            return Err(AnoError::FPE(format!(
                "the ciphertext value: {} must be lower or equal to {}",
                big_ciphertext, self.max_value
            )));
        }
        let digits = self.digits;
        let str_value = format!("{:0>digits$}", big_ciphertext.to_str_radix(self.radix));
        let plaintext = self.numeric_alphabet.decrypt(key, tweak, &str_value)?;

        BigUint::from_str_radix(&plaintext, self.radix)
            .map_err(|e| AnoError::FPE(format!("failed generating the plaintext value {}", e)))
    }

    /// The maximum value supported by this Integer
    pub fn max_value(&self) -> BigUint {
        self.max_value.clone()
    }

    /// The number of digits of the max value
    /// that is the same as the `radix^digits - 1`
    pub fn digits(&self) -> usize {
        self.digits
    }
}
