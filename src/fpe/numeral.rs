use std::str::FromStr;

use num_bigint::BigUint;
use num_traits::ToPrimitive;

use crate::{error::AnoError, fpe::FpeAlphabet};

use super::Alphabet;

pub struct Decimal {
    max_digits: usize,
    max_value: BigUint,
    numeric_alphabet: Alphabet,
}

impl Decimal {
    pub fn from(max_digits: usize) -> Result<Self, AnoError> {
        let max_value = BigUint::from_str(&format!("{:9<max_digits$}", 9)).map_err(|e| {
            AnoError::FPE(format!("failed generating the maximum decimal value {}", e))
        })?;

        Ok(Decimal {
            max_digits,
            max_value,
            numeric_alphabet: Alphabet::numeric(),
        })
    }

    pub fn encrypt(&self, value: u64, key: &[u8; 32], tweak: &[u8]) -> Result<u64, AnoError> {
        let big_value = BigUint::from(value);
        if big_value > self.max_value {
            return Err(AnoError::FPE(format!(
                "the value: {} must be lower or equal to {}",
                value, big_value
            )));
        }

        let max_digits = self.max_digits;
        let str_value = format!("{:0>max_digits$}", big_value.to_string());

        //encrypt
        let ciphertext = self.numeric_alphabet.encrypt(key, tweak, &str_value)?;
        println!(
            "original value: {}, rescaled value: {}, ciphertext: {}",
            value, str_value, ciphertext
        );
        let big_ciphertext = BigUint::from_str(&ciphertext)
            .map_err(|e| AnoError::FPE(format!("failed generating the ciphertext value {}", e)))?;
        big_ciphertext.to_u64().ok_or_else(|| {
            AnoError::FPE(format!(
                "failed converting the ciphertext value: {}, to an u64",
                big_ciphertext
            ))
        })
    }

    pub fn decrypt(&self, ciphertext: u64, key: &[u8; 32], tweak: &[u8]) -> Result<u64, AnoError> {
        let big_value = BigUint::from(ciphertext);
        if big_value > self.max_value {
            return Err(AnoError::FPE(format!(
                "the ciphertext value: {} must be lower or equal to {}",
                ciphertext, self.max_value
            )));
        }
        let plaintext = self
            .numeric_alphabet
            .decrypt(key, tweak, &big_value.to_string())?;
        let big_plaintext = BigUint::from_str(&plaintext)
            .map_err(|e| AnoError::FPE(format!("failed generating the plaintext value {}", e)))?;
        big_plaintext.to_u64().ok_or_else(|| {
            AnoError::FPE(format!(
                "failed converting the plaintext value: {}, to an u64",
                big_plaintext
            ))
        })
    }
}
