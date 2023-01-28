use crate::{ano_bail, ano_ensure, error::AnoError};
use itertools::Itertools;
use std::{collections::HashMap, convert::TryFrom, vec::Vec};
pub const RECOMMENDED_THRESHOLD: usize = 1_000_000;

/// `RebasedInput` gives the representation of the text string to encode in a
/// new integer base
#[derive(Default)]
pub struct RebasedInput {
    /// The number of characters in alphabet
    /// For example, 10 for the alphabet "0123456789"
    pub(crate) radix: u32,
    /// The text being represented a the new base.
    /// The base used for this representation depends on the alphabet length.
    /// For example, if alphabet is "0123456789", the base used is base-10
    /// (decimal base)
    pub(crate) input: Vec<u16>,
    /// The original string as a char vector (for convenience)
    pub(crate) original_chars: Vec<char>,
    /// The indexes of chars being rebased in the original string
    pub(crate) rebased_chars_original_indexes: Vec<usize>,
    /// The indexes of chars being excluded (everything not in alphabet)
    pub(crate) excluded_chars_indexes: Vec<usize>,
    /// Mapping between orignal char representation and the integer new
    /// representation
    pub(crate) mapping: HashMap<char, u8>,
}

///
impl RebasedInput {
    // According to the given alphabet, get the plaintext (or ciphertext) in a new
    // integer `base` starting from 0.
    pub fn rebase_text(input: &str, alphabet: &str) -> Result<Self, AnoError> {
        ano_ensure!(!input.is_empty(), "Cannot rebased empty input");
        ano_ensure!(
            !alphabet.is_empty(),
            "Alphabet is empty. No FPE encryption possible"
        );

        // Our final result
        let mut result = Self::default();

        // We want to exclude characters not being in alphabet
        // But we want to keep a reference of them (excluded_chars)
        let mut stripped_input = String::new();
        for (idx, char) in input.chars().enumerate() {
            result.original_chars.push(char);
            if alphabet.find(char).is_some() {
                stripped_input.push(char);
                result.rebased_chars_original_indexes.push(idx);
            } else {
                result.excluded_chars_indexes.push(idx);
            }
        }

        ano_ensure!(
            !stripped_input.is_empty(),
            "Input does not contain any characters of the alphabet! input={} alphabet={}",
            input,
            alphabet
        );
        // Check if FPE is usable (in a security point of view, verifying the
        // threshold as suggested in NIST standard https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
        ano_ensure!(
            alphabet.len() ^ stripped_input.len() < RECOMMENDED_THRESHOLD,
            "Given alphabet length ({}), plaintext is too short. Plaintext length should be at \
             least {}",
            alphabet.len(),
            (RECOMMENDED_THRESHOLD as f32).log(alphabet.len() as f32)
        );

        // Fill the mapping between original representation ("ABCDEFG...") and
        // new base representation ("01234567...")
        let alphabet = alphabet.chars().sorted().unique().collect::<Vec<_>>();
        for i in 0_u8..u8::try_from(alphabet.len())? {
            result.mapping.insert(alphabet[i as usize], i);
        }

        // Finally rebase input string according to the new base
        for c in stripped_input.chars() {
            match result.mapping.get(&c) {
                Some(matching_char) => result.input.push(u16::from(*matching_char)),
                None => ano_bail!("Cannot map input_text char {}", c),
            }
        }

        // Quick compute of radix (for convenience)
        result.radix = u32::try_from(alphabet.len())?;

        Ok(result)
    }

    // Revert rebase for the given char
    pub fn revert_rebase(&self, integer: u16) -> Result<char, AnoError> {
        let mut result = '0';
        for (k, v) in self.mapping.clone() {
            if u8::try_from(integer)? == v {
                result = k;
                break;
            }
        }
        Ok(result)
    }

    pub fn revert_rebase_vec(&self, input: Vec<u16>) -> Result<String, AnoError> {
        let mut result = String::new();
        for e in input {
            result += self.revert_rebase(e)?.to_string().as_str();
        }
        Ok(result)
    }

    pub fn reconstruct_original_format(&self, input: Vec<u16>) -> Result<String, AnoError> {
        let result = self.revert_rebase_vec(input)?;
        let result = self.reinsert_excluded_chars(result);
        Ok(result)
    }

    pub fn reinsert_excluded_chars(&self, input: String) -> std::string::String {
        let mut result = input;
        for idx in self.excluded_chars_indexes.clone() {
            result.insert(idx, self.original_chars[idx]);
        }
        result
    }

    pub fn _reinsert_negative_sign(&self, input: String) -> std::string::String {
        let mut result = input;
        for idx in self.excluded_chars_indexes.clone() {
            if idx != 0 {
                continue;
            }
            let char = self.original_chars[idx];
            if char == '-' {
                result.insert(idx, self.original_chars[idx]);
                break;
            }
        }
        result
    }

    pub fn remove_left_padding(&self, cleartext: String) -> std::string::String {
        // Remove left padding
        let mut is_0 = true;
        let mut result = String::new();
        for i in cleartext.chars() {
            // Ignore sign
            if i == '-' {
                result.push(i);
                continue;
            }
            if i == '0' && is_0 {
                continue;
            }
            is_0 = false;
            result.push(i)
        }
        if result.is_empty() {
            result.push('0');
        }
        result
    }
}
