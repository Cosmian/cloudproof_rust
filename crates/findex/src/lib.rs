//! Defines Findex interfaces for other languages.

pub mod backends;

#[cfg(any(
    feature = "backend-ffi",
    feature = "backend-python",
    feature = "backend-redis",
    feature = "backend-rest",
    feature = "backend-sqlite",
    feature = "backend-wasm",
))]
mod instantiation;

#[cfg(any(feature = "ffi", feature = "python", feature = "wasm"))]
pub mod interfaces;

#[cfg(any(test, feature = "ffi"))]
pub mod logger;

#[cfg(feature = "serialization")]
pub mod ser_de;

#[cfg(any(
    feature = "backend-ffi",
    feature = "backend-python",
    feature = "backend-redis",
    feature = "backend-rest",
    feature = "backend-sqlite",
    feature = "backend-wasm",
))]
pub use instantiation::{BackendConfiguration, InstantiatedFindex};
