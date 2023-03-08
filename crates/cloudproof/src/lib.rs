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
