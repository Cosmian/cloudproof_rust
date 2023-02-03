use crate::error::AnoError;
use itertools::Itertools;

use super::{fpe_alphabet::min_plaintext_length, FpeAlphabet};

/// The `Alphabet` structure contains information about the usable characters and the padding character in FPE.
pub struct Alphabet {
    /// Vector of characters that can be used in FPE
    pub(crate) chars: Vec<char>,
    /// Minimum length required for plaintext for FPE to be secure
    pub(crate) min_text_length: usize,
}

impl TryFrom<&str> for Alphabet {
    type Error = AnoError;

    fn try_from(alphabet: &str) -> Result<Self, Self::Error> {
        let chars = alphabet.chars().sorted().unique().collect_vec();
        if chars.len() < 2 || chars.len() >= 1 << 16 {
            return Err(AnoError::FPE(format!("Alphabet must contain between 2 and 2^16 characters. This alphabet contains {} characters",chars.len())));
        }
        Ok(Alphabet {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        })
    }
}

impl TryFrom<&String> for Alphabet {
    type Error = AnoError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Alphabet::try_from(value.as_str())
    }
}

impl Alphabet {
    /// Creates a new `Alphabet` with the specified string containing the usable characters
    pub fn new(chars: &[char]) -> Self {
        let chars = chars.iter().cloned().sorted().unique().collect_vec();
        Alphabet {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }

    fn extend_(&mut self, additional_characters: Vec<char>) {
        self.chars.extend(additional_characters);
        // Sort the characters and remove duplicates
        self.chars = self
            .chars
            .iter()
            .sorted()
            .unique()
            .cloned()
            .collect::<Vec<_>>();
        // Calculate the minimum text length for the extended alphabet
        self.min_text_length = min_plaintext_length(self.chars.len());
    }
}

impl FpeAlphabet for Alphabet {
    /// Returns the minimum length of the plaintext for FPE to be secure.
    /// The minimum text length is calculated based on a recommended threshold and the number of characters in the alphabet.
    fn minimum_plaintext_length(&self) -> usize {
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
    fn extend_with(&mut self, additional_characters: &str) {
        self.extend_(additional_characters.chars().collect::<Vec<_>>())
    }

    fn alphabet_len(&self) -> usize {
        self.chars.len()
    }

    fn char_to_position(&self, c: char) -> Option<u16> {
        match self.chars.binary_search(&c) {
            Ok(pos) => Some(pos as u16),
            Err(_) => None,
        }
    }

    fn to_string(&self) -> String {
        self.chars.iter().collect::<String>()
    }

    fn char_from_position(&self, position: u16) -> Option<char> {
        let pos = position as usize;
        if pos >= self.chars.len() {
            return None;
        }
        Some(self.chars[pos])
    }
}

// Use a macro to define functions with similar functionality but different names
macro_rules! define_alphabet_constructors {
    ($($name:ident => $alphabet:expr),+) => {
        $(
            impl Alphabet {
                /// Creates an Alphabet with the given alphabet string
                pub fn $name() -> Alphabet {
                    Alphabet::try_from($alphabet).unwrap()
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

impl Alphabet {
    /// The first 63489 (~2^16) Unicode characters
    pub fn utf() -> Alphabet {
        let chars = (0..=1 << 16_u32)
            .into_iter()
            .filter_map(char::from_u32)
            .collect::<Vec<char>>();
        println!(
            "LEN {}",
            chars.iter().skip(10000).take(200).collect::<String>()
        );
        Alphabet {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }
}
