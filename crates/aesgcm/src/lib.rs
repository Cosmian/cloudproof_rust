#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "python")]
pub mod pyo3;

#[cfg(feature = "wasm_bindgen")]
pub mod wasm_bindgen;

mod core;
mod error;
