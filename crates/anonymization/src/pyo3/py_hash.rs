use pyo3::{exceptions::PyException, prelude::*};

use crate::core::{HashMethod, Hasher as HasherRust};

#[pyclass]
pub struct Hasher(HasherRust);

#[pymethods]
impl Hasher {
    #[new]
    fn new(hasher_method: &str, salt: Option<Vec<u8>>) -> PyResult<Self> {
        let method = match hasher_method {
            "SHA2" => Ok(HashMethod::SHA2),
            "SHA3" => Ok(HashMethod::SHA3),
            "Argon2" => Ok(HashMethod::Argon2),
            _ => Err(PyException::new_err("Not a valid hash method specified.")),
        }?;

        Ok(Self(HasherRust { method, salt }))
    }

    pub fn apply(&self, data: &[u8]) -> PyResult<String> {
        Ok(pyo3_unwrap!(
            self.0.apply(data),
            "Error applying hash method"
        ))
    }
}
