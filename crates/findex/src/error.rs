//! Defines error type and conversions for Findex.

use std::fmt::Display;

#[cfg(feature = "wasm_bindgen")]
use wasm_bindgen::JsValue;

#[derive(Debug)]
pub enum Error {
    Wasm(String),
    Python(String),
    Ffi(String),
    Sqlite(String),
    Cloud(String),

    Io(String),
    SerdeJson(String),
    Base64(String),

    Crypto(String),
    Findex(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wasm(msg)
            | Self::Python(msg)
            | Self::Ffi(msg)
            | Self::Sqlite(msg)
            | Self::Cloud(msg)
            | Self::Io(msg)
            | Self::SerdeJson(msg)
            | Self::Base64(msg)
            | Self::Crypto(msg)
            | Self::Findex(msg) => {
                write!(f, "{msg}")
            }
        }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Self::Base64(format!("Base64 error: {e}"))
    }
}

impl From<Error> for cosmian_findex::error::FindexErr {
    fn from(e: Error) -> Self {
        Self::Other(format!("Cloudproof error: {e}"))
    }
}

impl From<cosmian_findex::error::FindexErr> for Error {
    fn from(e: cosmian_findex::error::FindexErr) -> Self {
        Self::Findex(format!("Findex error: {e}"))
    }
}

impl From<cosmian_crypto_core::CryptoCoreError> for Error {
    fn from(e: cosmian_crypto_core::CryptoCoreError) -> Self {
        Self::Crypto(format!("Crypto error: {e}"))
    }
}

#[cfg(feature = "sqlite")]
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(format!("Rusqlite error: {e}"))
    }
}

#[cfg(feature = "sqlite")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(format!("Io error: {e}"))
    }
}

#[cfg(any(feature = "sqlite", feature = "ffi"))]
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeJson(format!("Serde json error: {e}"))
    }
}

#[cfg(feature = "wasm_bindgen")]
impl From<Error> for JsValue {
    fn from(e: Error) -> Self {
        Self::from_str(&e.to_string())
    }
}

#[cfg(feature = "wasm_bindgen")]
impl From<JsValue> for Error {
    fn from(e: JsValue) -> Self {
        Self::Wasm(format!("Wasm error: {e:?}"))
    }
}

#[cfg(feature = "python")]
impl From<Error> for pyo3::PyErr {
    fn from(e: Error) -> Self {
        pyo3::exceptions::PyException::new_err(format!("{e}"))
    }
}
