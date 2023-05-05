use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::core::{
    WordMasker as WordMaskerRust, WordPatternMasker as WordPatternMaskerRust,
    WordTokenizer as WordTokenizerRust,
};

#[wasm_bindgen]
pub struct WordMasker(WordMaskerRust);

#[wasm_bindgen]
impl WordMasker {
    #[wasm_bindgen(constructor)]
    pub fn new(words_to_block: String) -> Self {
        let words_to_block: Vec<&str> = words_to_block.split(';').map(str::trim).collect();

        Self(WordMaskerRust::new(&words_to_block))
    }

    pub fn apply(&self, data: &str) -> Result<String, JsValue> {
        Ok(wasm_unwrap!(self.0.apply(data), "Error applying mask"))
    }
}

#[wasm_bindgen]
pub struct WordTokenizer(WordTokenizerRust);

#[wasm_bindgen]
impl WordTokenizer {
    #[wasm_bindgen(constructor)]
    pub fn new(words_to_block: String) -> Result<WordTokenizer, JsValue> {
        let words_to_block: Vec<&str> = words_to_block.split(';').map(str::trim).collect();

        Ok(Self(wasm_unwrap!(
            WordTokenizerRust::new(&words_to_block),
            "Error initializing WordTokenizer"
        )))
    }

    pub fn apply(&self, data: &str) -> Result<String, JsValue> {
        Ok(wasm_unwrap!(self.0.apply(data), "Error applying tokenizer"))
    }
}

#[wasm_bindgen]
pub struct WordPatternMasker(WordPatternMaskerRust);

#[wasm_bindgen]
impl WordPatternMasker {
    #[wasm_bindgen(constructor)]
    pub fn new(pattern_regex: &str, replace_str: &str) -> Result<WordPatternMasker, JsValue> {
        Ok(Self(wasm_unwrap!(
            WordPatternMaskerRust::new(pattern_regex, replace_str),
            "Error with the given Regex"
        )))
    }

    pub fn apply(&self, data: &str) -> String {
        self.0.apply(data)
    }
}
