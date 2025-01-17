#[cfg(feature = "wasm")]
use std::array::TryFromSliceError;
use std::{fmt::Display, num::TryFromIntError};

use cosmian_crypto_core::CryptoCoreError;
use cosmian_findex::CoreError as FindexCoreError;
#[cfg(feature = "wasm")]
use js_sys::{JsString, Object};
#[cfg(feature = "wasm")]
use wasm_bindgen::{JsCast, JsValue};

#[derive(Debug)]
pub struct SerializationError(String);

impl Display for SerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "serialization error: {}", self.0)
    }
}

impl std::error::Error for SerializationError {}

impl From<CryptoCoreError> for SerializationError {
    fn from(value: CryptoCoreError) -> Self {
        Self(value.to_string())
    }
}

impl From<FindexCoreError> for SerializationError {
    fn from(value: FindexCoreError) -> Self {
        Self(value.to_string())
    }
}

impl From<TryFromIntError> for SerializationError {
    fn from(value: TryFromIntError) -> Self {
        Self(value.to_string())
    }
}

#[cfg(feature = "wasm")]
impl From<TryFromSliceError> for SerializationError {
    fn from(value: TryFromSliceError) -> Self {
        Self(value.to_string())
    }
}

#[cfg(feature = "wasm")]
impl From<JsValue> for SerializationError {
    fn from(e: JsValue) -> Self {
        Self(format!(
            "Js error: {}",
            match e.dyn_ref::<JsString>() {
                Some(string) => format!("{string}"),
                None => match e.dyn_ref::<Object>() {
                    Some(object) => format!("{}", object.to_string()),
                    None => format!("{e:?}"),
                },
            }
        ))
    }
}

#[cfg(any(feature = "ffi", feature = "findex-cloud", feature = "rest-interface"))]
pub mod ffi_ser_de;
#[cfg(feature = "wasm")]
pub mod wasm_ser_de;
