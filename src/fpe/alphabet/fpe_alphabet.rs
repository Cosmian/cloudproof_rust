use aes::Aes256;
use fpe::ff1::{FF1h, FlexibleNumeralString};

use crate::{ano_ensure, error::AnoError};
use std::collections::HashMap;

/// The Key Length: 256 bit = 32 bytes for AES 256
pub const KEY_LENGTH: usize = 32;

/// The recommended threshold according to NIST standards
pub const RECOMMENDED_THRESHOLD: usize = 1_000_000;

/// Calculates the minimum length of the plaintext for FPE to be secure.
#[inline]
pub fn min_plaintext_length(alphabet_len: usize) -> usize {
    ((RECOMMENDED_THRESHOLD as f32).log(alphabet_len as f32)).ceil() as usize
}

pub trait FpeAlphabet {
    /// The number of characters in the alphabet
    fn alphabet_len(&self) -> usize;

    /// Returns the position of the given char in the alphabet
    fn char_to_position(&self, c: char) -> Option<u16>;

    /// Returns the alphabet char from its position in the alphabet
    fn char_from_position(&self, position: u16) -> Option<char>;

    /// Returns the minimum length of the plaintext for FPE to be secure.
    /// The minimum text length is calculated based on a recommended threshold and the number of characters in the alphabet.
    fn minimum_plaintext_length(&self) -> usize {
        min_plaintext_length(self.alphabet_len())
    }

    /// Creates a `RebasedString` from a `&str` by replacing every character in the input with the
    /// corresponding index in the `alphabet_chars` slice. Non-alphabet characters are stored as
    /// separate `u16` values and will be re-inserted into the output during the conversion back
    /// to a `String` using `to_string`.
    fn rebase(&self, input: &str) -> (Vec<u16>, HashMap<usize, char>) {
        let mut stripped_input: Vec<u16> = vec![];
        let mut non_alphabet_chars = HashMap::<usize, char>::new();
        for (idx, c) in input.chars().enumerate() {
            if let Some(pos) = self.char_to_position(c) {
                stripped_input.push(pos)
            } else {
                non_alphabet_chars.insert(idx, c);
            };
        }
        (stripped_input, non_alphabet_chars)
    }

    /// Converts the `RebasedString` back to a `String` using the `alphabet_chars` slice to look up
    /// the character representation of each `u16` value in the `stripped_input` vector. Non-alphabet
    /// characters stored in the `non_alphabet_chars` map are re-inserted into the output in the
    /// same position as they were in the original string.
    ///
    /// Returns a `Result` containing a `String` or an `AnoError` if the conversion fails.
    fn debase(
        &self,
        mut stripped_input: Vec<u16>,
        non_alphabet_chars: &HashMap<usize, char>,
    ) -> Result<String, AnoError> {
        // re-insert non alphabet chars
        let mut result = vec![];
        for i in 0..stripped_input.len() + non_alphabet_chars.len() {
            result.push(if let Some(c) = non_alphabet_chars.get(&i) {
                *c
            } else {
                let position = stripped_input.remove(0);
                self.char_from_position(position).ok_or_else(|| {
                    AnoError::FPE(format!(
                        "index {} out of bounds for alphabet of size {}",
                        position,
                        self.alphabet_len()
                    ))
                })?
            });
        }
        Ok(result.into_iter().collect::<String>())
    }

    /// Encrypts the plaintext using the given `key` and `tweak` using Format-Preserving Encryption (FPE).
    ///
    /// # Examples
    ///
    /// ```
    /// # use my_crate::{AnoError, FPE};
    /// let alphabet = Alphabet::new("abcdefghijklmnopqrstuvwxyz");
    /// let alphabet = Alphabet::alpha_lower(); //same as above
    /// let key = [0_u8; 32];
    /// let tweak = b"unique tweak";
    /// let plaintext = "plaintext";
    /// let ciphertext = alphabet.encrypt(&key, tweak, plaintext)?;
    /// assert_eq!(ciphertext, "phqivnqmo");
    /// # Ok::<(), AnoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the plaintext contains characters not in the alphabet, or if the encryption fails.
    fn encrypt(&self, key: &[u8], tweak: &[u8], plaintext: &str) -> Result<String, AnoError> {
        let (stripped_input, non_alphabet_chars) = self.rebase(plaintext);

        // Ensure the stripped input length meets the minimum security threshold
        ano_ensure!(
            stripped_input.len() >= self.minimum_plaintext_length(),
            "The stripped input length of {} is too short. It should be at least {} given the alphabet length of {}.",
            stripped_input.len(),
            self.minimum_plaintext_length(),
            self.alphabet_len()
        );

        if key.len() != KEY_LENGTH {
            return Err(AnoError::KeySize(key.len(), KEY_LENGTH));
        }

        let fpe_ff = FF1h::<Aes256>::new(key, self.alphabet_len() as u32)
            .map_err(|e| AnoError::FPE(format!("failed instantiating FF1: {}", e)))?;
        let ciphertext_ns = fpe_ff
            .encrypt(tweak, &FlexibleNumeralString::from(stripped_input))
            .map_err(|e| AnoError::FPE(format!("FF1 encryption failed: {}", e)))?;

        // Get ciphertext as u32-vector
        let ciphertext = Vec::<u16>::from(ciphertext_ns);

        self.debase(ciphertext, &non_alphabet_chars)
    }

    /// Decrypts the ciphertext using the given `key` and `tweak` using Format-Preserving Encryption (FPE).
    ///
    /// # Examples
    ///
    /// ```
    /// # use my_crate::{AnoError, FPE};
    /// let alphabet = Alphabet::new("abcdefghijklmnopqrstuvwxyz");
    /// let alphabet = Alphabet::alpha_lower(); //same as above
    /// let key = [0_u8; 32];
    /// let tweak = b"unique tweak";
    /// let ciphertext = "phqivnqmo";
    /// let cleartext = alphabet.decrypt(&key, tweak, &ciphertext)?;
    /// assert_eq!(cleartext, "plaintext");
    /// # Ok::<(), AnoError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext contains characters not in the alphabet, or if the decryption fails.
    fn decrypt(&self, key: &[u8], tweak: &[u8], ciphertext: &str) -> Result<String, AnoError> {
        let (stripped_input, non_alphabet_chars) = self.rebase(ciphertext);

        let fpe_ff = FF1h::<Aes256>::new(key, self.alphabet_len() as u32)
            .map_err(|e| AnoError::FPE(format!("failed instantiating FF1: {}", e)))?;
        let plaintext_ns = fpe_ff
            .decrypt(tweak, &FlexibleNumeralString::from(stripped_input))
            .map_err(|e| AnoError::FPE(format!("FF1 decryption failed: {}", e)))?;

        // Get plaintext as u32-vector
        let plaintext = Vec::<u16>::from(plaintext_ns);

        self.debase(plaintext, &non_alphabet_chars)
    }

    /// Extends the alphabet with additional characters.
    ///
    /// This method takes a string of additional characters as input and returns a new `Alphabet` that
    /// contains the characters of the original `Alphabet` as well as the additional characters. The new
    /// `Alphabet` has duplicates removed.
    ///
    /// # Arguments
    ///
    /// * `additional_characters` - A string of characters to be added to the alphabet.
    ///
    fn extend_with(&mut self, additional_characters: &str);

    /// Generate a string with all the alphabet characters
    fn to_string(&self) -> String;
}
