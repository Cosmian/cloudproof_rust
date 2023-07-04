//
// DO NOT REMOVE the following lines that are needed to force these crates to be
// linked into final cloudproof binaries (so, wasm or pyo3)
//
pub use cloudproof_aesgcm::wasm_bindgen as aesgcm_wasm_bindgen;
pub use cloudproof_cover_crypt::wasm_bindgen as cover_crypt_wasm_bindgen;
pub use cloudproof_ecies::wasm_bindgen as ecies_wasm_bindgen;
pub use cloudproof_findex::wasm_bindgen as findex_wasm_bindgen;
pub use cloudproof_fpe::wasm_bindgen as fpe_wasm_bindgen;
