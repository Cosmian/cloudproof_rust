//! Meta crate in order to merge other crates

#[cfg(feature = "ffi")]
pub use cloudproof_cover_crypt::ffi as cover_crypt_ffi;
#[cfg(feature = "python")]
pub use cloudproof_cover_crypt::pyo3 as cover_crypt_python;
#[cfg(feature = "wasm_bindgen")]
pub use cloudproof_cover_crypt::wasm_bindgen as cover_crypt_wasm_bindgen;
#[cfg(feature = "cloud")]
pub use cloudproof_findex::cloud as findex_cloud;
#[cfg(feature = "ffi")]
pub use cloudproof_findex::ffi as findex_ffi;
#[cfg(feature = "python")]
pub use cloudproof_findex::pyo3 as findex_python;
#[cfg(feature = "wasm_bindgen")]
pub use cloudproof_findex::wasm_bindgen as findex_wasm_bindgen;
#[cfg(feature = "ffi")]
pub use cloudproof_fpe::ffi as fpe_ffi;
#[cfg(feature = "python")]
pub use cloudproof_fpe::pyo3 as fpe_python;
#[cfg(feature = "wasm_bindgen")]
pub use cloudproof_fpe::wasm_bindgen as fpe_wasm_bindgen;

// re-export of CoverCrypt and Crypto Core
// so that projects that use their low level functionalities
// do  not have to depend on them directly, avoiding version conflicts.
#[cfg(feature = "default")]
pub mod reexport {
    pub use cloudproof_cover_crypt::reexport::{cover_crypt, crypto_core};
}
