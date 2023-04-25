//! Implement interfaces with other languages.

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "python")]
pub mod pyo3;

#[cfg(feature = "wasm_bindgen")]
pub mod wasm_bindgen;

// re-export of CoverCrypt and Crypto Core
// so that projects that use their low level functionalities
// do  not have to depend on them directly, avoiding version conflicts.
#[cfg(feature = "default")]
pub mod reexport {
    pub use cosmian_cover_crypt as cover_crypt;
    pub use cosmian_crypto_core as crypto_core;
}
