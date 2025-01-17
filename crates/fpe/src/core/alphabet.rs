use std::{collections::HashMap, fmt::Display};

use aes::Aes256;
use cosmian_fpe::ff1::{FF1h, FlexibleNumeralString};
use itertools::Itertools;

use super::AnoError;
use crate::{ano_ensure, core::KEY_LENGTH};

/// The recommended threshold according to NIST standards
pub const RECOMMENDED_THRESHOLD: usize = 1_000_000;

/// Calculates the minimum length of the plaintext for FPE to be secure.
pub fn min_plaintext_length(alphabet_len: usize) -> usize {
    ((RECOMMENDED_THRESHOLD as f32).log(alphabet_len as f32)).ceil() as usize
}

/// The `Alphabet` structure contains information about the usable characters
/// and the minimum plaintext length for FPE.
///
/// It's recommended that the alphabet contains between 8 and 2^16 characters.
/// Smaller alphabets as small as 2 characters are technically possible but can
/// be challenging to ensure security.
///
/// Pre-defined alphabets are available:
///  - `Alphabet::alpha()`
///  - `Alphabet::alpha_lower()`
///  - `Alphabet::alpha_upper()`
///  - `Alphabet::numeric()`
///  - `Alphabet::hexa_decimal()`
///  - `Alphabet::alpha_numeric()`
///  - `Alphabet::chinese()`
///  - `Alphabet::latin1sup()`
///  - `Alphabet::latin1sup_alphanum()`
///
/// To build your own, for example the hexadecimal alphabet,
/// use `Alphabet::try_from("0123456789abcdef").unwrap()`
///
/// See the `encrypt()` and `decrypt()` methods for usage
#[derive(Debug, Clone)]
pub struct Alphabet {
    /// Vector of characters that can be used in FPE
    pub(crate) chars: Vec<char>,
    /// Minimum length required for plaintext for FPE to be secure
    pub(crate) min_text_length: usize,
}

impl TryFrom<&str> for Alphabet {
    type Error = AnoError;

    /// Tries to create an `Alphabet` from a string slice of characters.
    ///
    /// # Arguments
    ///
    /// * `alphabet` - A string slice of the characters to be used as the
    ///   alphabet.
    ///
    /// # Returns
    ///
    /// An `Alphabet` if the string slice contains between 2 and 2^16
    /// characters, otherwise returns an error.
    fn try_from(alphabet: &str) -> Result<Self, Self::Error> {
        let chars = alphabet.chars().sorted().unique().collect_vec();
        if chars.len() < 2 || chars.len() >= 1 << 16 {
            return Err(AnoError::FPE(format!(
                "Alphabet must contain between 2 and 2^16 characters. This alphabet contains {} \
                 characters",
                chars.len()
            )));
        }
        Ok(Self {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        })
    }
}

impl TryFrom<&String> for Alphabet {
    type Error = AnoError;

    /// Tries to create an `Alphabet` from a string reference.
    ///
    /// # Arguments
    ///
    /// * `value` - A reference to a string of the characters to be used as the
    ///   alphabet.
    ///
    /// # Returns
    ///
    /// An `Alphabet` if the string contains between 2 and 2^16 characters,
    /// otherwise returns an error.
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl Alphabet {
    /// Tries to create an `Alphabet` from a string slice of characters.
    ///
    /// # Arguments
    ///
    /// * `alphabet` - A string slice of the characters to be used as the
    ///   alphabet.
    ///
    /// # Returns
    ///
    /// An `Alphabet` if the string slice contains between 2 and 2^16
    /// characters, otherwise returns an error.
    pub fn instantiate(alphabet: &str) -> Result<Self, AnoError> {
        Self::try_from(alphabet)
    }

    fn extend_(&mut self, additional_characters: Vec<char>) {
        self.chars.extend(additional_characters);
        // Sort the characters and remove duplicates
        self.chars = self
            .chars
            .iter()
            .sorted()
            .unique()
            .copied()
            .collect::<Vec<_>>();
        // Calculate the minimum text length for the extended alphabet
        self.min_text_length = min_plaintext_length(self.chars.len());
    }

    /// Returns the minimum length required for the plaintext for FPE to be
    /// secure. The minimum length is calculated based on the number of
    /// characters in the alphabet and recommended security thresholds.
    #[must_use]
    pub const fn minimum_plaintext_length(&self) -> usize {
        self.min_text_length
    }

    /// Extends the alphabet with additional characters.
    ///
    /// This method takes a string of additional characters as input and returns
    /// a new `Alphabet` that contains the characters of the original
    /// `Alphabet` as well as the additional characters. The new `Alphabet`
    /// has duplicates removed.
    ///
    /// # Arguments
    ///
    /// * `additional_characters` - A string of characters to be added to the
    ///   alphabet.
    pub fn extend_with(&mut self, additional_characters: &str) {
        self.extend_(additional_characters.chars().collect::<Vec<_>>());
    }

    /// Returns the number of characters in the alphabet.
    #[must_use]
    pub fn alphabet_len(&self) -> usize {
        self.chars.len()
    }

    /// Converts a character to its position within the alphabet.
    ///
    /// # Arguments
    ///
    /// * `c` - The character to be converted to its position.
    ///
    /// # Returns
    ///
    /// The position of the character within the alphabet, or `None` if the
    /// character is not present in the alphabet.
    pub(crate) fn char_to_position(&self, c: char) -> Option<u16> {
        match self.chars.binary_search(&c) {
            Ok(pos) => Some(pos as u16),
            Err(_) => None,
        }
    }

    /// Converts a position within the alphabet to its corresponding character.
    ///
    /// # Arguments
    ///
    /// * `position` - The position within the alphabet to be converted to its
    ///   corresponding character.
    ///
    /// # Returns
    ///
    /// The character at the specified position, or `None` if the position is
    /// outside the range of the alphabet.
    pub(crate) fn char_from_position(&self, position: u16) -> Option<char> {
        let pos = position as usize;
        if pos >= self.chars.len() {
            return None;
        }
        Some(self.chars[pos])
    }

    /// Creates a `RebasedString` from a `&str` by replacing every character in
    /// the input with the corresponding index in the `alphabet_chars`
    /// slice. Non-alphabet characters are stored as separate `u16` values
    /// and will be re-inserted into the output during the conversion back
    /// to a `String` using `to_string`.
    fn rebase(&self, input: &str) -> (Vec<u16>, HashMap<usize, char>) {
        let mut stripped_input: Vec<u16> = vec![];
        let mut non_alphabet_chars = HashMap::<usize, char>::new();
        for (idx, c) in input.chars().enumerate() {
            if let Some(pos) = self.char_to_position(c) {
                stripped_input.push(pos);
            } else {
                non_alphabet_chars.insert(idx, c);
            };
        }
        (stripped_input, non_alphabet_chars)
    }

    /// Converts the `RebasedString` back to a `String` using the
    /// `alphabet_chars` slice to look up the character representation of
    /// each `u16` value in the `stripped_input` vector. Non-alphabet
    /// characters stored in the `non_alphabet_chars` map are re-inserted into
    /// the output in the same position as they were in the original string.
    ///
    /// Returns a `Result` containing a `String` or an `AnoError` if the
    /// conversion fails.
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

    /// Encrypts the plaintext using the given `key` and `tweak` using
    /// Format-Preserving Encryption (FPE).
    ///
    /// # Examples
    ///
    /// ```
    /// use cloudproof_fpe::core::Alphabet;
    ///
    /// let alphabet = Alphabet::try_from("abcdefghijklmnopqrstuvwxyz").unwrap();
    /// let alphabet = Alphabet::alpha_lower(); //same as above
    /// let key = [0_u8; 32];
    /// let tweak = b"unique tweak";
    /// let plaintext = "plaintext";
    /// let ciphertext = alphabet.encrypt(&key, tweak, plaintext).unwrap();
    /// assert_eq!(ciphertext, "phqivnqmo");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the plaintext contains characters not in the
    /// alphabet, or if the encryption fails.
    pub fn encrypt(&self, key: &[u8], tweak: &[u8], plaintext: &str) -> Result<String, AnoError> {
        let (stripped_input, non_alphabet_chars) = self.rebase(plaintext);

        // Ensure the stripped input length meets the minimum security threshold
        ano_ensure!(
            stripped_input.len() >= self.minimum_plaintext_length(),
            "The stripped input length of {} is too short. It should be at least {} given the \
             alphabet length of {}.",
            stripped_input.len(),
            self.minimum_plaintext_length(),
            self.alphabet_len()
        );

        if key.len() != KEY_LENGTH {
            return Err(AnoError::KeySize(key.len(), KEY_LENGTH));
        }

        let fpe_ff = FF1h::<Aes256>::new(key, self.alphabet_len() as u32)
            .map_err(|e| AnoError::FPE(format!("failed instantiating FF1: {e}")))?;
        let ciphertext_ns = fpe_ff
            .encrypt(tweak, &FlexibleNumeralString::from(stripped_input))
            .map_err(|e| AnoError::FPE(format!("FF1 encryption failed: {e}")))?;

        // Get ciphertext as u32-vector
        let ciphertext = Vec::<u16>::from(ciphertext_ns);

        self.debase(ciphertext, &non_alphabet_chars)
    }

    /// Decrypts the ciphertext using the given `key` and `tweak` using
    /// Format-Preserving Encryption (FPE).
    ///
    /// # Examples
    ///
    /// ```
    /// use cloudproof_fpe::core::Alphabet;
    ///
    /// let alphabet = Alphabet::try_from("abcdefghijklmnopqrstuvwxyz").unwrap();
    /// let alphabet = Alphabet::alpha_lower(); //same as above
    /// let key = [0_u8; 32];
    /// let tweak = b"unique tweak";
    /// let ciphertext = "phqivnqmo";
    /// let cleartext = alphabet.decrypt(&key, tweak, &ciphertext).unwrap();
    /// assert_eq!(cleartext, "plaintext");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext contains characters not in the
    /// alphabet, or if the decryption fails.
    pub fn decrypt(&self, key: &[u8], tweak: &[u8], ciphertext: &str) -> Result<String, AnoError> {
        let (stripped_input, non_alphabet_chars) = self.rebase(ciphertext);

        let fpe_ff = FF1h::<Aes256>::new(key, self.alphabet_len() as u32)
            .map_err(|e| AnoError::FPE(format!("failed instantiating FF1: {e}")))?;
        let plaintext_ns = fpe_ff
            .decrypt(tweak, &FlexibleNumeralString::from(stripped_input))
            .map_err(|e| AnoError::FPE(format!("FF1 decryption failed: {e}")))?;

        // Get plaintext as u32-vector
        let plaintext = Vec::<u16>::from(plaintext_ns);

        self.debase(plaintext, &non_alphabet_chars)
    }
}

impl Display for Alphabet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.chars.iter().collect::<String>()))
    }
}

// Use a macro to define functions with similar functionality but different
// names
macro_rules! define_alphabet_constructors {
    ($($name:ident => $alphabet:expr),+) => {
        $(
            impl Alphabet {
                #[doc = "Creates an Alphabet with the given alphabet string: `"]
                #[doc = $alphabet]
                #[doc = "`."]
                #[must_use] pub fn $name() -> Alphabet {
                    Alphabet::try_from($alphabet).unwrap()
                }
            }
        )+
    }
}

define_alphabet_constructors! {
    numeric => "0123456789",
    hexa_decimal => "0123456789abcdef",
    alpha_lower => "abcdefghijklmnopqrstuvwxyz",
    alpha_upper => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    alpha => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    alpha_numeric => "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
}

impl Alphabet {
    /// Creates an Alphabet with the first 63489 (~2^16) Unicode characters
    pub fn utf() -> Self {
        let chars = (0..=1 << 16_u32)
            .filter_map(char::from_u32)
            .collect::<Vec<char>>();
        Self {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }

    /// Creates an Alphabet with the Chinese characters
    pub fn chinese() -> Self {
        let chars = (0x4E00..=0x9FFF_u32)
            .filter_map(char::from_u32)
            .collect::<Vec<char>>();
        Self {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }

    /// Creates an Alphabet with the latin-1 and latin1-supplement characters
    /// (supports French)
    pub fn latin1sup() -> Self {
        let chars = (0x0021..=0x007E_u32)
            .chain(0x00C0..=0x00FF)
            .filter_map(char::from_u32)
            .collect::<Vec<char>>();
        Self {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }

    /// Creates an Alphabet with the latin-1 and latin1-supplement characters
    /// but without the non alphanumeric characters (supports French)
    pub fn latin1sup_alphanum() -> Self {
        let chars = (0x0030..=0x0039_u32)
            .chain(0x0041..=0x005A)
            .chain(0x0061..=0x007A)
            .chain(0x00C0..=0x00FF)
            .filter_map(char::from_u32)
            .collect::<Vec<char>>();
        Self {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }
}
