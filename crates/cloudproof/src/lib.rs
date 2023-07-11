//! Meta crate in order to merge other crates

#[cfg(feature = "ffi")]
pub use cloudproof_aesgcm::ffi as aesgcm_ffi;
#[cfg(feature = "ffi")]
pub use cloudproof_anonymization::ffi as anonymization_ffi;
#[cfg(feature = "ffi")]
pub use cloudproof_cover_crypt::ffi as cover_crypt_ffi;
#[cfg(feature = "ffi")]
pub use cloudproof_ecies::ffi as ecies_ffi;
#[cfg(feature = "ffi")]
pub use cloudproof_findex::ffi as findex_ffi;
#[cfg(feature = "ffi")]
pub use cloudproof_fpe::ffi as fpe_ffi;

// re-export of CoverCrypt and Crypto Core
// so that projects that use their low level functionalities
// do  not have to depend on them directly, avoiding version conflicts.
#[cfg(feature = "default")]
pub mod reexport {
    pub use cloudproof_anonymization as anonymization;
    pub use cloudproof_cover_crypt::reexport::{cover_crypt, crypto_core};
    pub use cloudproof_findex as findex;
    pub use cloudproof_fpe as fpe;
}
