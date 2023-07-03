#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "python")]
pub mod pyo3;

#[cfg(feature = "wasm_bindgen")]
pub mod wasm_bindgen;

mod core;
mod error;

pub use crate::core::aesgcm::{ReExposedAesGcm, BLOCK_LENGTH, KEY_LENGTH, NONCE_LENGTH};
