use core::fmt::Display;
use std::{array::TryFromSliceError, num::TryFromIntError};

use cosmian_crypto_core::CryptoCoreError;
#[cfg(feature = "ffi")]
use cosmian_ffi_utils::ErrorCode;
use cosmian_findex::{CoreError as FindexCoreError, DbInterfaceErrorTrait};
#[cfg(feature = "wasm")]
use js_sys::{JsString, Object};
#[cfg(feature = "redis-interface")]
use redis::RedisError;
#[cfg(feature = "sqlite-interface")]
use rusqlite::Error as RusqliteError;
#[cfg(feature = "wasm")]
use wasm_bindgen::JsCast;
#[cfg(feature = "wasm")]
use wasm_bindgen::JsValue;

#[cfg(any(feature = "rest-interface", feature = "wasm", feature = "ffi"))]
use crate::ser_de::SerializationError;

#[derive(Debug)]
pub enum DbInterfaceError {
    #[cfg(feature = "sqlite-interface")]
    Rusqlite(RusqliteError),
    #[cfg(feature = "redis-interface")]
    Redis(RedisError),
    MissingCallback(String),
    #[cfg(feature = "ffi")]
    Ffi(String, ErrorCode),
    #[cfg(feature = "python")]
    Python(String),
    #[cfg(feature = "rest-interface")]
    MalformedToken(String),
    #[cfg(feature = "wasm")]
    Wasm(String),
    #[cfg(feature = "rest-interface")]
    MissingPermission(i32),
    Findex(FindexCoreError),
    CryptoCore(CryptoCoreError),
    Serialization(String),
    IntConversion(TryFromIntError),
    SliceConversion(TryFromSliceError),
    Other(String),
    Io(std::io::Error),
}

impl Display for DbInterfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "sqlite-interface")]
            Self::Rusqlite(err) => write!(f, "rusqlite: {err}"),
            #[cfg(feature = "redis-interface")]
            Self::Redis(err) => write!(f, "redis: {err}"),
            Self::MissingCallback(err) => write!(f, "unknown callback: {err}"),
            #[cfg(feature = "ffi")]
            Self::Ffi(err, code) => write!(f, "{err}: {code}"),
            #[cfg(feature = "rest-interface")]
            Self::MalformedToken(err) => write!(f, "{err}"),
            #[cfg(feature = "python")]
            Self::Python(err) => write!(f, "{err}"),
            #[cfg(feature = "wasm")]
            Self::Wasm(err) => write!(f, "wasm callback error: {err}"),
            #[cfg(feature = "rest-interface")]
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

impl std::error::Error for DbInterfaceError {}

impl DbInterfaceErrorTrait for DbInterfaceError {}

#[cfg(feature = "sqlite-interface")]
impl From<RusqliteError> for DbInterfaceError {
    fn from(e: RusqliteError) -> Self {
        Self::Rusqlite(e)
    }
}

#[cfg(feature = "redis-interface")]
impl From<RedisError> for DbInterfaceError {
    fn from(e: RedisError) -> Self {
        Self::Redis(e)
    }
}

#[cfg(any(feature = "rest-interface", feature = "wasm", feature = "ffi"))]
impl From<SerializationError> for DbInterfaceError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<TryFromIntError> for DbInterfaceError {
    fn from(e: TryFromIntError) -> Self {
        Self::IntConversion(e)
    }
}

#[cfg(feature = "rest-interface")]
impl From<TryFromSliceError> for DbInterfaceError {
    fn from(e: TryFromSliceError) -> Self {
        Self::SliceConversion(e)
    }
}

impl From<CryptoCoreError> for DbInterfaceError {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptoCore(e)
    }
}

impl From<FindexCoreError> for DbInterfaceError {
    fn from(e: FindexCoreError) -> Self {
        Self::Findex(e)
    }
}

impl From<std::io::Error> for DbInterfaceError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(feature = "wasm")]
impl From<JsValue> for DbInterfaceError {
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
