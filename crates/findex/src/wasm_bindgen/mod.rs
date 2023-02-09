//! Defines the WASM interface for Findex.

use std::fmt::Display;

use cosmian_findex::CallbackError;
use js_sys::{JsString, Object};
use wasm_bindgen::{JsCast, JsValue};

macro_rules! wasm_unwrap {
    ($res:expr, $msg:literal) => {
        $res.map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}: {e:?}", $msg)))?
    };
    ($res:expr, $msg:expr) => {
        $res.map_err(|_| wasm_bindgen::JsValue::from_str($msg.as_str()))?
    };
}

pub mod api;
pub mod core;

#[derive(Debug)]
pub enum FindexWasmError {
    MissingCallback(String),
    Callback(String),
    JsError(JsValue),
}

impl Display for FindexWasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCallback(error) => write!(f, "missing callback: {error}"),
            Self::Callback(error) => write!(f, "callback error: {error}"),
            Self::JsError(error) => match error.dyn_ref::<JsString>() {
                Some(string) => write!(f, "{string}"),
                None => match error.dyn_ref::<Object>() {
                    // Object in Err is often an `Error` with a simple toString()
                    Some(object) => write!(f, "{}", object.to_string()),
                    // If it's neither a string, nor an object, print the debug JsValue.
                    None => write!(f, "{error:?}"),
                },
            },
        }
    }
}

impl From<JsValue> for FindexWasmError {
    fn from(value: JsValue) -> Self {
        Self::JsError(value)
    }
}

impl std::error::Error for FindexWasmError {}

impl CallbackError for FindexWasmError {}
