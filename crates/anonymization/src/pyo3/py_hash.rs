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

    pub fn apply(&self, data: &[u8]) -> PyResult<String> {
        Ok(pyo3_unwrap!(
            self.0.apply(data),
            "Error applying hash method"
        ))
    }
}
