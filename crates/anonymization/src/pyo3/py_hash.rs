use pyo3::prelude::*;

use crate::core::{HashMethod, Hasher as HasherRust};

#[pyclass]
pub struct Hasher(HasherRust);

#[pymethods]
impl Hasher {
    #[new]
    fn new(hasher_method: &str, salt_opt: Option<Vec<u8>>) -> PyResult<Self> {
        let method = pyo3_unwrap!(
            HashMethod::new(hasher_method, salt_opt),
            "Error initializing the hasher"
        );

        Ok(Self(HasherRust::new(method)))
    }

    pub fn apply_str(&self, data: &str) -> PyResult<String> {
        Ok(pyo3_unwrap!(
            self.0.apply_str(data),
            "Error applying hash method"
        ))
    }

    pub fn apply_bytes(&self, data: &[u8]) -> PyResult<Vec<u8>> {
        Ok(pyo3_unwrap!(
            self.0.apply_bytes(data),
            "Error applying hash method"
        ))
    }
}
