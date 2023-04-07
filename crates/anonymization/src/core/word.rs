use std::collections::HashSet;

use regex::Regex;

use super::AnoError;

pub struct WordTokenizer {}

pub struct WordMasker {
    word_list: HashSet<String>,
}

impl WordMasker {
    #[must_use] pub fn new(words_to_block: &[&str]) -> Self {
        Self {
            word_list: words_to_block.iter().map(|s| s.to_lowercase()).collect(),
        }
    }

    pub fn apply(&self, data: &str) -> Result<String, AnoError> {
        let re = Regex::new(r"[[:punct:]\s]+")?;
        let split_vec: Vec<&str> = re.split(data).collect();

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
