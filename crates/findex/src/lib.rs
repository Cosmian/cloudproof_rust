//! Defines Findex interfaces for other languages.

pub mod db_interfaces;

#[cfg(any(
    feature = "ffi",
    feature = "python",
    feature = "redis-interface",
    feature = "rest-interface",
    feature = "sqlite-interface",
    feature = "wasm",
))]
mod instantiation;

#[cfg(any(feature = "ffi", feature = "python", feature = "wasm"))]
pub mod interfaces;

#[cfg(any(test, feature = "ffi"))]
pub mod logger;

#[cfg(feature = "serialization")]
pub mod ser_de;

#[cfg(any(
    feature = "ffi",
    feature = "python",
    feature = "redis-interface",
    feature = "rest-interface",
    feature = "sqlite-interface",
    feature = "wasm",
))]
pub use instantiation::{Configuration, InstantiatedFindex};
