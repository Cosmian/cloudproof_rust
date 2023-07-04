use std::fmt::Display;

#[cfg(feature = "python")]
use pyo3::{exceptions::PyException, PyErr};
#[cfg(feature = "wasm_bindgen")]
use wasm_bindgen::JsValue;

#[derive(Debug)]
pub enum AesGcmError {
    AesGcm(String),
    AesGcmInvalidLength(String),
}

impl Display for AesGcmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AesGcm(err) => write!(f, "{err}"),
            Self::AesGcmInvalidLength(err) => write!(f, "{err}"),
        }
    }
}

impl From<aes_gcm::Error> for AesGcmError {
    fn from(value: aes_gcm::Error) -> Self {
        Self::AesGcm(value.to_string())
    }
}
impl From<aes_gcm::aes::cipher::InvalidLength> for AesGcmError {
    fn from(value: aes_gcm::aes::cipher::InvalidLength) -> Self {
        Self::AesGcmInvalidLength(value.to_string())
    }
}

#[cfg(feature = "wasm_bindgen")]
impl From<AesGcmError> for JsValue {
    fn from(value: AesGcmError) -> Self {
        Self::from_str(&format!("Cloudproof error: {value:?}"))
    }
}

#[cfg(feature = "python")]
impl From<AesGcmError> for PyErr {
    fn from(value: AesGcmError) -> Self {
        PyException::new_err(format!("Cloudproof error: {value:?}"))
    }
}
