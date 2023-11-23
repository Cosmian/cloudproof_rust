use core::fmt::Display;
use std::{array::TryFromSliceError, num::TryFromIntError};

use cosmian_crypto_core::CryptoCoreError;
#[cfg(feature = "backend-ffi")]
use cosmian_ffi_utils::ErrorCode;
use cosmian_findex::{BackendErrorTrait, CoreError as FindexCoreError};
#[cfg(feature = "backend-wasm")]
use js_sys::{JsString, Object};
#[cfg(feature = "backend-redis")]
use redis::RedisError;
#[cfg(feature = "backend-sqlite")]
use rusqlite::Error as RusqliteError;
#[cfg(feature = "backend-wasm")]
use wasm_bindgen::JsCast;
#[cfg(feature = "backend-wasm")]
use wasm_bindgen::JsValue;

#[cfg(any(
    feature = "backend-ffi",
    feature = "backend-rest",
    feature = "backend-wasm",
    feature = "ffi"
))]
use crate::ser_de::SerializationError;

#[derive(Debug)]
pub enum BackendError {
    #[cfg(feature = "backend-sqlite")]
    Rusqlite(RusqliteError),
    #[cfg(feature = "backend-redis")]
    Redis(RedisError),
    MissingCallback(String),
    #[cfg(feature = "backend-ffi")]
    Ffi(String, ErrorCode),
    #[cfg(feature = "backend-python")]
    Python(String),
    #[cfg(feature = "backend-rest")]
    MalformedToken(String),
    #[cfg(feature = "backend-wasm")]
    Wasm(String),
    #[cfg(feature = "backend-rest")]
    MissingPermission(i32),
    Findex(FindexCoreError),
    CryptoCore(CryptoCoreError),
    Serialization(String),
    IntConversion(TryFromIntError),
    SliceConversion(TryFromSliceError),
    Other(String),
    Io(std::io::Error),
}

impl Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "backend-sqlite")]
            Self::Rusqlite(err) => write!(f, "rusqlite: {err}"),
            #[cfg(feature = "backend-redis")]
            Self::Redis(err) => write!(f, "redis: {err}"),
            Self::MissingCallback(err) => write!(f, "unknown callback: {err}"),
            #[cfg(feature = "backend-ffi")]
            Self::Ffi(err, code) => write!(f, "{err}: {code}"),
            #[cfg(feature = "backend-rest")]
            Self::MalformedToken(err) => write!(f, "{err}"),
            #[cfg(feature = "backend-python")]
            Self::Python(err) => write!(f, "{err}"),
            #[cfg(feature = "backend-wasm")]
            Self::Wasm(err) => write!(f, "wasm callback error: {err}"),
            #[cfg(feature = "backend-rest")]
            Self::MissingPermission(err) => write!(f, "missing permission: {err}"),
            Self::CryptoCore(err) => write!(f, "crypto_core: {err}"),
            Self::Findex(err) => write!(f, "findex: {err}"),
            Self::Io(err) => write!(f, "io: {err}"),
            Self::Serialization(err) => write!(f, "serialization: {err}"),
            Self::IntConversion(err) => write!(f, "conversion: {err}"),
            Self::SliceConversion(err) => write!(f, "conversion: {err}"),
            Self::Other(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for BackendError {}

impl BackendErrorTrait for BackendError {}

#[cfg(feature = "backend-sqlite")]
impl From<RusqliteError> for BackendError {
    fn from(e: RusqliteError) -> Self {
        Self::Rusqlite(e)
    }
}

#[cfg(feature = "backend-redis")]
impl From<RedisError> for BackendError {
    fn from(e: RedisError) -> Self {
        Self::Redis(e)
    }
}

#[cfg(any(
    feature = "backend-ffi",
    feature = "backend-rest",
    feature = "backend-wasm",
    feature = "ffi"
))]
impl From<SerializationError> for BackendError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<TryFromIntError> for BackendError {
    fn from(e: TryFromIntError) -> Self {
        Self::IntConversion(e)
    }
}

#[cfg(feature = "backend-rest")]
impl From<TryFromSliceError> for BackendError {
    fn from(e: TryFromSliceError) -> Self {
        Self::SliceConversion(e)
    }
}

impl From<CryptoCoreError> for BackendError {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptoCore(e)
    }
}

impl From<FindexCoreError> for BackendError {
    fn from(e: FindexCoreError) -> Self {
        Self::Findex(e)
    }
}

impl From<std::io::Error> for BackendError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(feature = "backend-wasm")]
impl From<JsValue> for BackendError {
    fn from(e: JsValue) -> Self {
        Self::Wasm(format!(
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
