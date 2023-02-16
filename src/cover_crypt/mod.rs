//! Implement interfaces with other languages.

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "python")]
pub mod pyo3;

#[cfg(feature = "wasm")]
pub mod wasm;
