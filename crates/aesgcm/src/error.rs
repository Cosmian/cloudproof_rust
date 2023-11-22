use std::{array::TryFromSliceError, fmt::Display};

use cosmian_crypto_core::CryptoCoreError;
#[cfg(feature = "python")]
use pyo3::{exceptions::PyException, PyErr};
#[cfg(feature = "wasm")]
use wasm_bindgen::JsValue;

#[derive(Debug)]
pub enum AesGcmError {
    CryptoCore(CryptoCoreError),
    TryFromSliceError(TryFromSliceError),
}

impl Display for AesGcmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CryptoCore(err) => write!(f, "{err}"),
            Self::TryFromSliceError(err) => write!(f, "{err}"),
        }
    }
}

impl From<CryptoCoreError> for AesGcmError {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptoCore(e)
    }
}

impl From<TryFromSliceError> for AesGcmError {
    fn from(e: TryFromSliceError) -> Self {
        Self::TryFromSliceError(e)
    }
}

#[cfg(feature = "wasm")]
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
