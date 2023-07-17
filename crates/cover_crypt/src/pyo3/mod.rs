use pyo3::{pymodule, types::PyModule, PyResult, Python};

/// Implements the basic functionalities of a key in python.
///
/// - implements `deep_copy`
/// - converts to and from `PyBytes`
///
/// # Parameters
///
/// - `type_name`   : name of the key type
macro_rules! impl_key_byte {
    ($py_type:ty, $rust_type:ty) => {
        #[pymethods]
        impl $py_type {
            /// Clones the key
            pub fn deep_copy(&self) -> Self {
                Self(self.0.clone())
            }

            /// Converts key to bytes
            pub fn to_bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
                Ok(PyBytes::new(
                    py,
                    &self
                        .0
                        .serialize()
                        .map_err(|e| PyTypeError::new_err(e.to_string()))?,
                )
                .into())
            }

            /// Reads key from bytes
            #[staticmethod]
            pub fn from_bytes(key_bytes: &[u8]) -> PyResult<Self> {
                match <$rust_type>::deserialize(key_bytes) {
                    Ok(key) => Ok(Self(key)),
                    Err(e) => Err(PyTypeError::new_err(e.to_string())),
                }
            }
        }
    };
}

macro_rules! pyo3_unwrap {
    ($res:expr, $msg:literal) => {
        $res.map_err(|e| pyo3::exceptions::PyTypeError::new_err(format!("{}: {e:?}", $msg)))?
    };
}

mod py_abe_policy;
mod py_cover_crypt;

use py_abe_policy::{Attribute, Policy, PolicyAxis};
use py_cover_crypt::{CoverCrypt, MasterPublicKey, MasterSecretKey, SymmetricKey, UserSecretKey};

/// A Python module implemented in Rust.
#[pymodule]
fn cloudproof_cover_crypt(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Attribute>()?;
    m.add_class::<PolicyAxis>()?;
    m.add_class::<Policy>()?;
    m.add_class::<CoverCrypt>()?;
    m.add_class::<SymmetricKey>()?;
    m.add_class::<MasterSecretKey>()?;
    m.add_class::<MasterPublicKey>()?;
    m.add_class::<UserSecretKey>()?;
    Ok(())
}
