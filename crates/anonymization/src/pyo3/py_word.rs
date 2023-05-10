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
    pub fn new(words_list: Vec<&str>) -> Self {
        Self(WordMaskerRust::new(&words_list))
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
    pub fn new(words_list: Vec<&str>) -> PyResult<Self> {
        Ok(Self(pyo3_unwrap!(
            WordTokenizerRust::new(&words_list),
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
    pub fn new(pattern: &str, replace: &str) -> PyResult<Self> {
        Ok(Self(pyo3_unwrap!(
            WordPatternMaskerRust::new(pattern, replace),
            "Error with the given Regex"
        )))
    }

    pub fn apply(&self, data: &str) -> String {
        self.0.apply(data)
    }
}
