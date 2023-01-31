use super::rebased_input::RebasedInput;
use crate::{ano_ensure, error::AnoError};
use aes::Aes256;
use fpe::ff1::{FF1h, FlexibleNumeralString};
use num_traits::bounds::Bounded;
use std::{convert::TryFrom, fmt::Display, str::FromStr, vec::Vec};
// pub const RECOMMENDED_THRESHOLD: usize = 1_000_000;
pub const KEY_LENGTH: usize = 32;
// pub const NONCE_LENGTH: usize = 0;
// pub const MAC_LENGTH: usize = 0;

#[allow(clippy::upper_case_acronyms)]
#[derive(Default)]
pub struct FPE;

impl Display for FPE {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FF1 with 18 Feistel Rounds and AES 256")
    }
}

impl PartialEq for FPE {
    // `rng` is a random generator so you obviously can't
    // compare with other `rng` instance
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

/// `FF1Crypto` gives multiple encryption/decryption functions.
/// Those different functions differ in the type of the input string
/// representation.
/// The most usable functions are `encrypt_string` and `encrypt_digit_string`
/// Those 2 last functions force the input string to be rebased in a new integer
/// base (base 10 for example in case of digit string)
impl FPE {
    pub fn encrypt_u16(
        key: &[u8],
        tweak: &[u8],
        radix: u32,
        plaintext: Vec<u16>,
    ) -> Result<Vec<u16>, AnoError> {
        if key.len() != KEY_LENGTH {
            return Err(AnoError::KeySize(key.len(), KEY_LENGTH));
        }

        let fpe_ff = FF1h::<Aes256>::new(key, radix).expect("failed building new FF1");
        let ciphertext = fpe_ff
            .encrypt(tweak, &FlexibleNumeralString::from(plaintext))
            .expect("FF1 encrypting failed");

        // Get ciphertext as u16-vector
        let ciphertext_vec = Vec::<u16>::from(ciphertext);

        Ok(ciphertext_vec)
    }

    pub fn decrypt_u16(
        key: &[u8],
        tweak: &[u8],
        radix: u32,
        ciphertext: Vec<u16>,
    ) -> Result<Vec<u16>, AnoError> {
        if key.len() != KEY_LENGTH {
            return Err(AnoError::KeySize(key.len(), KEY_LENGTH));
        }

        let fpe_ff = FF1h::<Aes256>::new(key, radix).expect("failed building new FF1");
        let cleartext = fpe_ff
            .decrypt(tweak, &FlexibleNumeralString::from(ciphertext))
            .expect("FF1 decrypting failed");
        // Get cleartext as u16-vector
        let cleartext_vec = Vec::<u16>::from(cleartext);
        Ok(cleartext_vec)
    }

    pub fn encrypt_u8(
        key: &[u8],
        tweak: &[u8],
        radix: u32,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, AnoError> {
        let plaintext = plaintext.into_iter().map(u16::from).collect::<Vec<_>>();
        let ciphertext = Self::encrypt_u16(key, tweak, radix, plaintext)?;
        let mut result = Vec::with_capacity(ciphertext.len());
        for e in ciphertext {
            result.push(u8::try_from(e).map_err(|e| AnoError::ConversionError(e.to_string()))?);
        }
        Ok(result)
    }

    pub fn decrypt_u8(
        key: &[u8],
        tweak: &[u8],
        radix: u32,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, AnoError> {
        let ciphertext = ciphertext.into_iter().map(u16::from).collect::<Vec<_>>();
        let cleartext = Self::decrypt_u16(key, tweak, radix, ciphertext)?;
        let mut result = Vec::with_capacity(cleartext.len());
        for e in cleartext {
            result.push(u8::try_from(e).map_err(|e| AnoError::ConversionError(e.to_string()))?);
        }
        Ok(result)
    }

    /// In `encrypt_string`, we put aside all characters not being in alphabet.
    /// We keep the index of those characters in the original string to put them
    /// back in the final encrypted string.
    pub fn encrypt_string(
        key: &[u8],
        tweak: &[u8],
        alphabet: &str,
        plaintext: &str,
    ) -> Result<String, AnoError> {
        ano_ensure!(alphabet.len() >=8, "An alphabet of {} characters is too small to ensure security, it should be at least 8 characters",alphabet.len());

        let rebased = RebasedInput::rebase_text(&format!("{:>8}", plaintext), alphabet)?;

        let ciphertext = Self::encrypt_u16(key, tweak, rebased.radix, rebased.input.clone())?;

        // Represent the ciphertext in the original plaintext base
        let result = rebased.reconstruct_original_format(ciphertext)?;

        Ok(result)
    }

    pub fn decrypt_string(
        key: &[u8],
        tweak: &[u8],
        alphabet: &str,
        ciphertext: &str,
    ) -> Result<String, AnoError> {
        let rebased = RebasedInput::rebase_text(ciphertext, alphabet)?;

        let cleartext = Self::decrypt_u16(key, tweak, rebased.radix, rebased.input.clone())?;

        // Represent the cleartext in the original plaintext base
        let result = rebased.reconstruct_original_format(cleartext)?;

        Ok(result)
    }

    /// Like in `encrypt_string`, we put aside the characters not being in
    /// alphabet. The difference with `encrypt_string` is the left padding that
    /// occurs. Indeed, we want to deal with very small input digit string (like
    /// number on less than 6 characters) and respect the security threshold
    /// given in NIST 800 38G (`radix^minlen>1_000_000`). This padding will be
    /// done according to the given input type (the generic `T`). For example,
    /// for a `u32` type, the left-zeroes-padding will pad the input string
    /// until 9 characters (not more because of the max u32 possible value).
    pub fn encrypt_digit_string<T>(
        key: &[u8],
        tweak: &[u8],
        plaintext: &str,
    ) -> Result<String, AnoError>
    where
        T: ToString + Bounded + FromStr + PartialOrd + Ord,
        <T as std::str::FromStr>::Err: std::error::Error,
    {
        let alphabet = ('0'..='9').collect::<String>();
        let rebased = RebasedInput::rebase_text(plaintext, alphabet.as_str())?;

        let expected_output_length = T::max_value().to_string().len() - 1;
        ano_ensure!(
            expected_output_length > 0,
            "Expect output length cannot be 0"
        );

        if rebased.input.len() <= expected_output_length {
            // Add custom left padding for digit string whose length is less than
            // expected_output_length
            let padding_size = usize::min(
                expected_output_length - rebased.input.len(),
                if rebased.input.len() >= 6 {
                    rebased.input.len()
                } else {
                    6 - rebased.input.len()
                },
            );
            let mut padded_plaintext = vec![0_u16; padding_size];
            padded_plaintext.extend_from_slice(&rebased.input);

            let ciphertext = Self::encrypt_u16(key, tweak, rebased.radix, padded_plaintext)?;
            // Represent the ciphertext in the original plaintext base
            let result = rebased.reconstruct_original_format(ciphertext)?;
            let numeric_result = result
                .parse::<T>()
                .expect("Encryption digit strings leads to an unparsable digit-strings");
            ano_ensure!(
                numeric_result >= T::min_value() && numeric_result <= T::max_value(),
                "Encrypted digit strings lead to an integer overflow"
            );
            Ok(result)
        } else {
            let left = &rebased.input[0..rebased.input.len() - expected_output_length];
            let right = &rebased.input[rebased.input.len() - expected_output_length..];
            let right_plaintext = rebased.revert_rebase_vec(right.to_vec())?;
            let right_ciphertext = Self::encrypt_digit_string::<T>(key, tweak, &right_plaintext)?;
            let left = rebased.revert_rebase_vec(left.to_vec())?;
            let result = format!("{}{}", left, right_ciphertext);
            let result = rebased.reinsert_excluded_chars(result);

            Ok(result)
        }
    }

    pub fn decrypt_digits_string<T>(
        key: &[u8],
        tweak: &[u8],
        ciphertext: &str,
    ) -> Result<String, AnoError>
    where
        T: ToString + Bounded,
    {
        let alphabet = ('0'..='9').collect::<String>();
        let rebased = RebasedInput::rebase_text(ciphertext, alphabet.as_str())?;

        let expected_output_length = T::max_value().to_string().len() - 1;
        ano_ensure!(
            expected_output_length > 0,
            "Expect output length cannot be 0"
        );

        if rebased.input.len() <= expected_output_length {
            let cleartext = Self::decrypt_u16(key, tweak, rebased.radix, rebased.input.clone())?;
            let result = rebased.reconstruct_original_format(cleartext)?;
            let result = rebased.remove_left_padding(result);
            Ok(result)
        } else {
            let left = &rebased.input[0..rebased.input.len() - expected_output_length];
            let right = &rebased.input[rebased.input.len() - expected_output_length..];
            let right_ciphertext = rebased.revert_rebase_vec(right.to_vec())?;
            let mut result = Self::decrypt_digits_string::<T>(key, tweak, &right_ciphertext)?;

            // This is unexpected when decrypted right part begins with 0. Those zeroes must
            // be considered as padding
            if result.len() < expected_output_length {
                let removed_zeroes_length = expected_output_length - result.len();
                let removed_zeroes_string =
                    (0..removed_zeroes_length).map(|_| "0").collect::<String>();
                result = format!("{}{}", removed_zeroes_string, result);
            }
            let left = rebased.revert_rebase_vec(left.to_vec())?;
            let result = format!("{}{}", left, result);
            let result = rebased.reinsert_excluded_chars(result);
            Ok(result)
        }
    }
}
