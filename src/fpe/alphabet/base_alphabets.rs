use crate::error::AnoError;
use itertools::Itertools;

use super::{fpe_alphabet::min_plaintext_length, FpeAlphabet};

/// The `Alphabet` structure contains information about the usable characters and the minimum plaintext length for FPE.
///
/// It's recommended that the alphabet contains between 8 and 2^16 characters.
/// Smaller alphabets as small as 2 characters are technically possible but can be challenging to ensure security.
///
/// Pre-defined alphabets are available:
///  - `Alphabet::alpha()`
///  - `Alphabet::alpha_lower()`
///  - `Alphabet::alpha_upper()`
///  - `Alphabet::numeric()`
///  - `Alphabet::alpha_numeric()`
///  - `Alphabet::chinese()`
///  - `Alphabet::latin1sup()`
///  - `Alphabet::latin1sup_alphanum()`
///
/// To build your own, for example the hexadecimal alphabet,  
/// use `Alphabet::try_from("0123456789abcdef").unwrap()`
///
/// See the `encrypt()` and `decrypt()` methods for usage
///
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
    /// * `alphabet` - A string slice of the characters to be used as the alphabet.
    ///
    /// # Returns
    ///
    /// An `Alphabet` if the string slice contains between 2 and 2^16 characters, otherwise returns an error.
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

    /// Tries to create an `Alphabet` from a string reference.
    ///
    /// # Arguments
    ///
    /// * `value` - A reference to a string of the characters to be used as the alphabet.
    ///
    /// # Returns
    ///
    /// An `Alphabet` if the string contains between 2 and 2^16 characters, otherwise returns an error.
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Alphabet::try_from(value.as_str())
    }
}

impl Alphabet {
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
    /// Returns the minimum length required for the plaintext for FPE to be secure. The minimum length is
    /// calculated based on the number of characters in the alphabet and recommended security thresholds.
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
    fn extend_with(&mut self, additional_characters: &str) {
        self.extend_(additional_characters.chars().collect::<Vec<_>>())
    }

    /// Returns the number of characters in the alphabet.
    fn alphabet_len(&self) -> usize {
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
    /// The position of the character within the alphabet, or `None` if the character is not present in the alphabet.
    fn char_to_position(&self, c: char) -> Option<u16> {
        match self.chars.binary_search(&c) {
            Ok(pos) => Some(pos as u16),
            Err(_) => None,
        }
    }

    /// Returns the alphabet as a string.
    fn to_string(&self) -> String {
        self.chars.iter().collect::<String>()
    }

    /// Converts a position within the alphabet to its corresponding character.
    ///
    /// # Arguments
    ///
    /// * `position` - The position within the alphabet to be converted to its corresponding character.
    ///
    /// # Returns
    ///
    /// The character at the specified position, or `None` if the position is outside the range of the alphabet.
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
                #[doc = "Creates an Alphabet with the given alphabet string: `"]
                #[doc = $alphabet]
                #[doc = "`."]
                pub fn $name() -> Alphabet {
                    Alphabet::try_from($alphabet).unwrap()
                }
            }
        )+
    }
}

define_alphabet_constructors! {
    numeric => "0123456789",
    alpha_lower => "abcdefghijklmnopqrstuvwxyz",
    alpha_upper => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    alpha => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    alpha_numeric => "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
}

impl Alphabet {
    /// Creates an Alphabet with the first 63489 (~2^16) Unicode characters
    pub fn utf() -> Alphabet {
        let chars = (0..=1 << 16_u32)
            .into_iter()
            .filter_map(char::from_u32)
            .collect::<Vec<char>>();
        Alphabet {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }

    /// Creates an Alphabet with the Chinese characters
    pub fn chinese() -> Alphabet {
        let chars = (0x4E00..=0x9FFF_u32)
            .into_iter()
            .filter_map(char::from_u32)
            .collect::<Vec<char>>();
        Alphabet {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }

    /// Creates an Alphabet with the latin-1 and latin1-supplement characters
    /// (supports French)
    pub fn latin1sup() -> Alphabet {
        let chars = (0x0021..=0x007E_u32)
            .chain(0x00C0..=0x00FF)
            .into_iter()
            .filter_map(char::from_u32)
            .collect::<Vec<char>>();
        Alphabet {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }

    /// Creates an Alphabet with the latin-1 and latin1-supplement characters
    /// but without the non alphanumeric characters (supports French)
    pub fn latin1sup_alphanum() -> Alphabet {
        let chars = (0x0030..=0x0039_u32)
            .chain(0x0041..=0x005A)
            .chain(0x0061..=0x007A)
            .chain(0x00C0..=0x00FF)
            .into_iter()
            .filter_map(char::from_u32)
            .collect::<Vec<char>>();
        Alphabet {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }
}
