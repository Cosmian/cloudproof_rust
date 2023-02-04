use std::str::FromStr;

use num_bigint::BigUint;
use num_traits::ToPrimitive;

use crate::{error::AnoError, fpe::FpeAlphabet};

use super::Alphabet;

pub struct Decimal {
    pub(crate) digits: usize,
    pub(crate) max_value: BigUint,
    pub(crate) numeric_alphabet: Alphabet,
}

impl Decimal {
    /// Creates a new instance of the `Decimal` representation.
    /// It calculates the `max_value` as the number of `digits` digits with 9's.
    ///
    /// # Example
    /// ```
    /// use cosmian_anonymization::fpe::Decimal;
    /// use num_bigint::BigUint;
    ///
    /// let decimal = Decimal::from(8).unwrap();
    /// assert_eq!(decimal.digits(), 8);
    /// assert_eq!(decimal.max_value(), BigUint::from(99_999_999_u64));
    /// ```
    ///
    /// # Arguments
    /// `digits` - The maximum number of digits for the decimal representation.
    ///
    /// # Returns
    /// A new instance of `Decimal` representation.
    ///
    /// # Errors
    /// If the calculation of the maximum decimal value fails.
    pub fn from(digits: usize) -> Result<Self, AnoError> {
        if digits < 6 {
            return Err(AnoError::FPE(format!(
                "Decimal: the number of digits should be at least 6, {} were provided.",
                digits
            )));
        }

        let max_value = BigUint::from_str(&format!("{:9<digits$}", 9)).map_err(|e| {
            AnoError::FPE(format!("failed generating the maximum decimal value {}", e))
        })?;

        Ok(Decimal {
            digits,
            max_value,
            numeric_alphabet: Alphabet::numeric(),
        })
    }

    /// Encrypts a given `value` using the FPE method.
    /// The value must be lower or equal to the `max_value` of the decimal representation.
    ///
    /// # Example
    /// ```
    /// use cosmian_anonymization::fpe::Decimal;
    ///
    /// let decimal = Decimal::from(8).unwrap();
    /// let key = [0u8; 32];
    /// let tweak = b"tweak";
    ///
    /// let encrypted = decimal.encrypt(100, &key, tweak).unwrap();
    /// assert_ne!(100, encrypted);
    ///
    /// let decrypted = decimal.decrypt(encrypted, &key, tweak).unwrap();
    /// assert_eq!(100, decrypted);
    /// ```
    ///
    /// # Arguments
    /// `value` - The decimal value to encrypt.
    /// `key` - Key used for encryption.
    /// `tweak` - Tweak
    pub fn encrypt(&self, value: u64, key: &[u8; 32], tweak: &[u8]) -> Result<u64, AnoError> {
        let ciphertext = self.encrypt_big(&BigUint::from(value), key, tweak)?;
        ciphertext.to_u64().ok_or_else(|| {
            AnoError::FPE(format!(
                "failed converting the ciphertext value: {}, to an u64",
                ciphertext
            ))
        })
    }

    /// Encrypts a given `value` using the FPE method.
    /// The value must be lower or equal to the `max_value` of the decimal representation.
    ///
    /// # Example
    /// ```
    /// use cosmian_anonymization::fpe::Decimal;
    /// use num_bigint::BigUint;
    ///
    /// let decimal = Decimal::from(8).unwrap();
    /// let key = [0u8; 32];
    /// let tweak = b"tweak";
    ///
    /// let encrypted = decimal.encrypt_big(&BigUint::from(100_u64), &key, tweak).unwrap();
    /// assert_ne!(BigUint::from(100_u64), encrypted);
    ///
    /// let decrypted = decimal.decrypt_big(&encrypted, &key, tweak).unwrap();
    /// assert_eq!(BigUint::from(100_u64), decrypted);
    /// ```
    ///
    /// # Arguments
    /// `value` - The decimal value to encrypt.
    /// `key` - Key used for encryption.
    /// `tweak` - Tweak
    pub fn encrypt_big(
        &self,
        big_value: &BigUint,
        key: &[u8; 32],
        tweak: &[u8],
    ) -> Result<BigUint, AnoError> {
        if big_value > &self.max_value {
            return Err(AnoError::FPE(format!(
                "the value: {} must be lower or equal to {}",
                big_value, self.max_value
            )));
        }

        let digits = self.digits;
        let str_value = format!("{:0>digits$}", big_value.to_string());

        //encrypt
        let ciphertext = self.numeric_alphabet.encrypt(key, tweak, &str_value)?;
        let big_ciphertext = BigUint::from_str(&ciphertext)
            .map_err(|e| AnoError::FPE(format!("failed generating the ciphertext value {}", e)))?;
        Ok(big_ciphertext)
    }

    /// Decrypts the given `ciphertext` using the specified `key` and `tweak` and returns the plaintext as an `u64`.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to be decrypted, represented as an `u64`.
    /// * `key` - A `&[u8; 32]` slice representing the encryption key.
    /// * `tweak` - A `&[u8]` slice representing the tweak value.
    ///
    /// # Returns
    ///
    /// Returns the plaintext as an `u64` if the decryption was successful.
    /// Returns an `AnoError` if the decryption was not successful.
    ///
    /// # Errors
    ///
    /// Returns an `AnoError` if:
    /// - The ciphertext value is greater than the maximum value set for the `Decimal` struct.
    /// - The plaintext could not be generated from the ciphertext string.
    /// - The plaintext value could not be converted to an `u64`.
    ///
    /// # Example
    ///
    /// ```
    /// use cosmian_anonymization::fpe::Decimal;
    ///
    /// let key = [0; 32];
    /// let tweak = [0];
    /// let decimal = Decimal::from(8).unwrap();
    /// let ciphertext = decimal.encrypt(123456, &key, &tweak).unwrap();
    /// let plaintext = decimal.decrypt(ciphertext, &key, &tweak).unwrap();
    /// assert_eq!(123456, plaintext);
    /// ```
    pub fn decrypt(&self, ciphertext: u64, key: &[u8; 32], tweak: &[u8]) -> Result<u64, AnoError> {
        let plaintext = self.decrypt_big(&BigUint::from(ciphertext), key, tweak)?;
        plaintext.to_u64().ok_or_else(|| {
            AnoError::FPE(format!(
                "failed converting the plaintext value: {}, to an u64",
                plaintext
            ))
        })
    }

    /// Decrypts the given `ciphertext` using the specified `key` and `tweak` and returns the plaintext as an `u64`.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to be decrypted, represented as an `u64`.
    /// * `key` - A `&[u8; 32]` slice representing the encryption key.
    /// * `tweak` - A `&[u8]` slice representing the tweak value.
    ///
    /// # Returns
    ///
    /// Returns the plaintext as an `u64` if the decryption was successful.
    /// Returns an `AnoError` if the decryption was not successful.
    ///
    /// # Errors
    ///
    /// Returns an `AnoError` if:
    /// - The ciphertext value is greater than the maximum value set for the `Decimal` struct.
    /// - The plaintext could not be generated from the ciphertext string.
    /// - The plaintext value could not be converted to an `u64`.
    ///
    /// # Example
    ///
    /// ```
    /// use cosmian_anonymization::fpe::Decimal;
    /// use num_bigint::BigUint;
    ///
    /// let key = [0; 32];
    /// let tweak = [0];
    /// let decimal = Decimal::from(8).unwrap();
    /// let ciphertext = decimal.encrypt_big(&BigUint::from(123456_u64), &key, &tweak).unwrap();
    /// let plaintext = decimal.decrypt_big(&ciphertext, &key, &tweak).unwrap();
    /// assert_eq!(BigUint::from(123456_u64), plaintext);
    /// ```
    pub fn decrypt_big(
        &self,
        big_ciphertext: &BigUint,
        key: &[u8; 32],
        tweak: &[u8],
    ) -> Result<BigUint, AnoError> {
        if big_ciphertext > &self.max_value {
            return Err(AnoError::FPE(format!(
                "the ciphertext value: {} must be lower or equal to {}",
                big_ciphertext, self.max_value
            )));
        }
        let digits = self.digits;
        let str_value = format!("{:0>digits$}", big_ciphertext.to_string());
        let plaintext = self.numeric_alphabet.decrypt(key, tweak, &str_value)?;
        BigUint::from_str(&plaintext)
            .map_err(|e| AnoError::FPE(format!("failed generating the plaintext value {}", e)))
    }

    /// The maximum value supported by this decimal
    pub fn max_value(&self) -> BigUint {
        self.max_value.clone()
    }

    /// The number of digits of the max value
    /// that is the same as the power of 10 minus 1
    pub fn digits(&self) -> usize {
        self.digits
    }
}
