use super::rebased_input::RebasedInput;
use crate::{ano_ensure, error::AnoError, fpe::FPE};
use itertools::Itertools;
use std::ops::Add;

/// The recommended threshold according to NIST standards
pub const RECOMMENDED_THRESHOLD: usize = 1_000_000;

/// Calculates the minimum length of the plaintext for FPE to be secure.
#[inline]
fn min_plaintext_length(alphabet_len: usize) -> usize {
    ((RECOMMENDED_THRESHOLD as f32).log(alphabet_len as f32)).ceil() as usize
}

/// The `Alphabet` structure contains information about the usable characters and the padding character in FPE.
pub struct Alphabet {
    /// Vector of characters that can be used in FPE
    pub(crate) chars: Vec<char>,
    /// Minimum length required for plaintext for FPE to be secure
    pub(crate) min_text_length: usize,
    /// The character used for padding
    pub(crate) pad_char: char,
}

impl Alphabet {
    /// Creates a new `Alphabet` with the specified string as the usable characters and a default padding character of `'◊'`
    pub fn new(alphabet: &str) -> Self {
        Self::new_using_pad(alphabet, '◊')
    }

    /// Creates a new `Alphabet` with the specified string as the usable characters and the specified padding character.
    pub fn new_using_pad(alphabet: &str, pad_char: char) -> Self {
        let chars = alphabet.chars().sorted().unique().collect_vec();
        Alphabet {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
            pad_char,
        }
    }

    /// Returns the minimum length of the plaintext for FPE to be secure.
    /// The minimum text length is calculated based on a recommended threshold and the number of characters in the alphabet.
    pub fn minimum_plaintext_length(&self) -> usize {
        self.min_text_length
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
    /// # Returns
    ///
    /// A new `Alphabet` that contains the characters of the original `Alphabet` as well as the additional characters.
    pub fn extend_with(&self, additional_characters: &str) -> Alphabet {
        self.extend_(additional_characters.chars().collect::<Vec<_>>())
    }
    fn extend_(&self, additional_characters: Vec<char>) -> Alphabet {
        let mut new_value = self.chars.clone();
        // Extend the original alphabet with the additional characters
        new_value.extend(additional_characters);
        // Sort the characters and remove duplicates
        let new_value = new_value.into_iter().sorted().unique().collect::<Vec<_>>();
        // Calculate the minimum text length for the extended alphabet
        let min_text_length = min_plaintext_length(new_value.len());
        // Return a new Alphabet with the extended characters
        Alphabet {
            chars: new_value,
            min_text_length,
            pad_char: self.pad_char,
        }
    }

    /// Rebase the given `input` string to a new base representation using the `Alphabet` characters.
    ///
    /// The resulting `RebasedInput` struct contains the mapping from the original representation
    /// to the new base representation, the radix of the new base representation, and the rebased input string.
    ///
    /// # Examples
    ///
    /// ```
    /// use ano_fpe::alphabet::{Alphabet, RebasedInput};
    ///
    /// let alphabet = Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    /// let input = "HELLO";
    /// let rebased = alphabet.rebase(input).unwrap();
    ///
    /// assert_eq!(rebased.input, vec![7, 4, 11, 11, 14]);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the stripped input length is shorter than the minimum required length,
    /// or if a character in the input string cannot be mapped to the new base representation.
    ///
    /// # Note
    ///
    /// The `min_text_length` property is used to check the usability of the FPE (in a security point of view, verifying
    /// the threshold as suggested in [NIST standard](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)).
    fn rebase(&self, input: &str) -> Result<RebasedInput, AnoError> {
        let mut result = RebasedInput::default();
        let mut stripped_input = String::new();

        // Strip characters not in the alphabet and keep a reference to their original positions
        for (idx, char) in input.chars().enumerate() {
            result.original_chars.push(char);
            if self.chars.contains(&char) {
                stripped_input.push(char);
                result.rebased_chars_original_indexes.push(idx);
            } else {
                result.excluded_chars_indexes.push(idx);
            }
        }

        // Ensure the stripped input length meets the minimum security threshold
        ano_ensure!(
            stripped_input.len() >= self.min_text_length,
            "The stripped input length of {} is too short. It should be at least {} given the alphabet length of {}.",
            stripped_input.len(),
            self.min_text_length,
            self.chars.len()
        );

        // Build the mapping between the original and new base representation
        for (i, char) in self.chars.iter().enumerate() {
            result.mapping.insert(*char, i as u8);
        }

        // Rebase the stripped input string to the new base representation
        for char in stripped_input.chars() {
            match result.mapping.get(&char) {
                Some(base) => result.input.push(*base as u16),
                None => {
                    return Err(AnoError::FPE(format!(
                        "Cannot map input character '{}'",
                        char
                    )))
                }
            }
        }

        // Store the radix for convenience
        result.radix = self.chars.len() as u32;

        Ok(result)
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
    pub fn encrypt(&self, key: &[u8], tweak: &[u8], plaintext: &str) -> Result<String, AnoError> {
        let rebased = self.rebase(plaintext)?;
        let ciphertext = FPE::encrypt_u16(key, tweak, rebased.radix, rebased.input.clone())?;
        let result = rebased.reconstruct_original_format(ciphertext)?;
        Ok(result)
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
    pub fn decrypt(&self, key: &[u8], tweak: &[u8], ciphertext: &str) -> Result<String, AnoError> {
        let rebased = self.rebase(ciphertext)?;
        let cleartext = FPE::decrypt_u16(key, tweak, rebased.radix, rebased.input.clone())?;
        let result = rebased.reconstruct_original_format(cleartext)?;
        Ok(result)
    }
}

/// Defines the `Add` trait for `Alphabet` structs to allow for concatenation of two alphabets.
impl Add for Alphabet {
    type Output = Alphabet;

    /// Returns a new `Alphabet` that is the result of concatenating `self` and `another_alphabet`.
    /// The set of characters in the new alphabet is the sorted and unique combination of characters from both alphabets.
    /// The minimum text length of the new alphabet is equal to the number of characters in the set.
    /// The padding character is inherited from `self`.
    fn add(self, another_alphabet: Self) -> Self::Output {
        self.extend_(another_alphabet.chars)
    }
}

// Use a macro to define functions with similar functionality but different names
macro_rules! define_alphabet_constructors {
    ($($name:ident => $alphabet:expr),+) => {
        $(
            impl Alphabet {
                /// Creates an Alphabet with the given alphabet string
                pub fn $name() -> Alphabet {
                    Alphabet::new($alphabet)
                }
            }
        )+
    }
}

// Define the following functions using the above macro:
// - Alphabet::alpha_lower
// - Alphabet::alpha_upper
// - Alphabet::alpha
// - Alphabet::alpha_numeric
define_alphabet_constructors! {
    numeric => "0123456789",
    alpha_lower => "abcdefghijklmnopqrstuvwxyz",
    alpha_upper => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    alpha => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    alpha_numeric => "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
}
