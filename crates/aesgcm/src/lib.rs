/// The `cloudproof_rust` subcrate `aesgcm` brings the standard AES256 GCM
/// implementation which has been audited by the NCC Group, with no significant
/// findings. Refer to https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "python")]
pub mod pyo3;

#[cfg(feature = "wasm_bindgen")]
pub mod wasm_bindgen;

mod core;
mod error;

pub use crate::core::aesgcm::{decrypt, encrypt};
