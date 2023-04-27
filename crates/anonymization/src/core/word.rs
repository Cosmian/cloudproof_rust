use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::CsRng;
use rand::{RngCore, SeedableRng};
use regex::Regex;

use super::AnoError;

pub struct WordTokenizer {
    /// A mapping of words to UUIDs.
    word_token_mapping: HashMap<String, String>,
}

impl WordTokenizer {
    /// Creates a new instance of `WordTokenizer`.
    ///
    /// # Arguments
    ///
    /// * `words_to_block`: a slice of strings representing the words to be
    ///   replaced with UUIDs.
    pub fn new(words_to_block: &[&str]) -> Result<Self, AnoError> {
        let mut mapping = HashMap::with_capacity(words_to_block.len());
        let mut rng = CsRng::from_entropy();

        for word in words_to_block {
            let mut uuid = [0; 16];
            rng.try_fill_bytes(&mut uuid)?;
            mapping.insert(word.to_lowercase(), hex::encode_upper(uuid));
        }
        Ok(Self {
            word_token_mapping: mapping,
        })
    }

    /// Remove sensitive words from a text by replacing them with tokens.
    ///
    /// # Arguments
    ///
    /// * `data`: a string representing the input text.
    ///
    /// # Returns
    ///
    /// Texts containing tokens in place of sensitive words.
    pub fn apply(&self, data: &str) -> Result<String, AnoError> {
        let re = Regex::new(r"\b\w+\b").unwrap();
        let result = re.replace_all(data, |caps: &regex::Captures| {
            match self.word_token_mapping.get(&caps[0].to_lowercase()) {
                Some(token) => token.to_string(),
                None => caps[0].to_string(),
            }
        });
        Ok(result.into_owned())
    }
}

pub struct WordMasker {
    /// A set of words to be masked in the text.
    word_list: HashSet<String>,
}

impl WordMasker {
    /// Creates a new `WordMasker` instance.
    ///
    /// # Arguments
    ///
    /// * `words_to_block`: A slice of string references containing the words to
    ///   be masked in the text.
    #[must_use]
    pub fn new(words_to_block: &[&str]) -> Self {
        Self {
            word_list: words_to_block.iter().map(|s| s.to_lowercase()).collect(),
        }
    }

    /// Masks the specified words in the given text.
    ///
    /// # Arguments
    ///
    /// * `data`: A string slice containing the text to be masked.
    ///
    /// # Returns
    ///
    /// Text without the sensitive words.
    pub fn apply(&self, data: &str) -> Result<String, AnoError> {
        let re = Regex::new(r"\b\w+\b").unwrap();
        let result = re.replace_all(data, |caps: &regex::Captures| {
            if self.word_list.contains(&caps[0].to_lowercase()) {
                "XXXX".to_string()
            } else {
                caps[0].to_string()
            }
        });
        Ok(result.into_owned())
    }
}

pub struct WordPatternMasker {
    pattern: Regex,
    replacer: String,
}

impl WordPatternMasker {
    /// Creates a new instance of `WordPatternMasker` with the provided pattern
    /// regex and replace string.
    ///
    /// # Arguments
    ///
    /// * `pattern_regex` - The pattern regex to search for.
    /// * `replace_str` - The string to replace the matched patterns.
    pub fn new(pattern_regex: &str, replace_str: &str) -> Result<Self, AnoError> {
        Ok(Self {
            pattern: Regex::new(pattern_regex)?,
            replacer: replace_str.to_string(),
        })
    }

    /// Applies the pattern mask to the provided data.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to be masked.
    ///
    /// # Returns
    ///
    /// Text with the matched pattern replaced.
    #[must_use]
    pub fn apply(&self, data: &str) -> String {
        self.pattern.replace(data, &self.replacer).into_owned()
    }
}
