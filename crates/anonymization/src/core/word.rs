use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::CsRng;
use rand::{RngCore, SeedableRng};
use regex::Regex;

use super::AnoError;

pub struct WordTokenizer {
    word_token_mapping: HashMap<String, [u8; 16]>,
    re_word_separator: Regex,
}

impl WordTokenizer {
    pub fn new(words_to_block: &[&str]) -> Result<Self, AnoError> {
        let mut mapping = HashMap::new();
        let mut rng = CsRng::from_entropy();

        for word in words_to_block {
            let mut uuid = [0; 16];
            rng.try_fill_bytes(&mut uuid)?;
            mapping.insert(word.to_lowercase(), uuid);
        }
        Ok(Self {
            word_token_mapping: mapping,
            re_word_separator: Regex::new(r"[[:punct:]\s]+").expect("Regex should always be valid"),
        })
    }

    pub fn apply(&self, data: &str) -> Result<String, AnoError> {
        let split_vec: Vec<&str> = self.re_word_separator.split(data).collect();

        let res: Vec<String> = split_vec
            .iter()
            .map(
                |word| match self.word_token_mapping.get(&word.to_lowercase()) {
                    Some(uuid) => hex::encode_upper(uuid),
                    None => (*word).to_string(),
                },
            )
            .collect();

        Ok(res.join(" "))
    }
}

pub struct WordMasker {
    word_list: HashSet<String>,
    re_word_separator: Regex,
}

impl WordMasker {
    #[must_use]
    pub fn new(words_to_block: &[&str]) -> Self {
        Self {
            word_list: words_to_block.iter().map(|s| s.to_lowercase()).collect(),
            re_word_separator: Regex::new(r"[[:punct:]\s]+").expect("Regex should always be valid"),
        }
    }

    pub fn apply(&self, data: &str) -> Result<String, AnoError> {
        let split_vec: Vec<&str> = self.re_word_separator.split(data).collect();

        let res: Vec<&str> = split_vec
            .iter()
            .map(|word| match self.word_list.contains(&word.to_lowercase()) {
                true => "XXXX",
                false => word,
            })
            .collect();

        Ok(res.join(" "))
    }
}

pub struct WordPatternMasker {
    pattern: Regex,
}

impl WordPatternMasker {
    pub fn new(pattern_regex: &str) -> Result<Self, AnoError> {
        Ok(Self {
            pattern: Regex::new(pattern_regex)?,
        })
    }

    pub fn apply(&self, data: &str) -> Result<String, AnoError> {
        Ok(self.pattern.replace(data, "XXXX").into_owned())
    }
}
