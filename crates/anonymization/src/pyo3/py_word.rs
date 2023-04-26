use pyo3::prelude::*;

use crate::core::{
    WordMasker as WordMaskerRust, WordPatternMasker as WordPatternMaskerRust,
    WordTokenizer as WordTokenizerRust,
};

#[pyclass]
pub struct WordMasker(WordMaskerRust);

#[pymethods]
impl WordMasker {
    #[new]
    pub fn new(words_to_block: Vec<&str>) -> Self {
        Self(WordMaskerRust::new(&words_to_block))
    }

    pub fn apply(&self, data: &str) -> PyResult<String> {
        Ok(pyo3_unwrap!(self.0.apply(data), "Error applying mask"))
    }
}

#[pyclass]
pub struct WordTokenizer(WordTokenizerRust);

#[pymethods]
impl WordTokenizer {
    #[new]
    pub fn new(words_to_block: Vec<&str>) -> PyResult<Self> {
        Ok(Self(pyo3_unwrap!(
            WordTokenizerRust::new(&words_to_block),
            "Error initializing WordTokenizer"
        )))
    }

    pub fn apply(&self, data: &str) -> PyResult<String> {
        Ok(pyo3_unwrap!(self.0.apply(data), "Error applying tokenizer"))
    }
}

#[pyclass]
pub struct WordPatternMasker(WordPatternMaskerRust);

#[pymethods]
impl WordPatternMasker {
    #[new]
    pub fn new(pattern_regex: &str, replace_str: &str) -> PyResult<Self> {
        Ok(Self(pyo3_unwrap!(
            WordPatternMaskerRust::new(pattern_regex, replace_str),
            "Error initializing WordPatternMasker"
        )))
    }

    pub fn apply(&self, data: &str) -> PyResult<String> {
        Ok(pyo3_unwrap!(self.0.apply(data), "Error matching pattern"))
    }
}
