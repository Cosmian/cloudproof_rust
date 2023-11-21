//! Defines the WASM interface for Findex.

use std::fmt::Display;

use cosmian_findex::Error as FindexError;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::backends::BackendError;

pub mod api;
pub mod types;

#[wasm_bindgen]
pub async fn webassembly_logger_init() {
    wasm_logger::init(wasm_logger::Config::default());
    log::info!("wasm_logger initialized");
}

#[derive(Debug)]
#[wasm_bindgen]
pub struct WasmError(String);

impl Display for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<BackendError> for WasmError {
    fn from(error: BackendError) -> Self {
        Self(format!("backend error: {error}"))
    }
}

impl From<FindexError<BackendError>> for WasmError {
    fn from(error: FindexError<BackendError>) -> Self {
        match error {
            FindexError::Callback(_) => Self(format!("backend error: {error}")),
            _ => Self(format!("findex error: {error}")),
        }
    }
}

impl std::error::Error for WasmError {}
