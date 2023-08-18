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

#[cfg(any(feature = "ffi", feature = "python", feature = "wasm_bindgen"))]
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

/// Error code returned by the callbacks.
///
/// They can be generated either by the Rust code or the FFI backend.
#[cfg(any(feature = "backend-ffi", feature = "ffi"))]
#[repr(i32)]
#[derive(Debug)]
pub enum ErrorCode {
    Success,
    BufferTooSmall,
    MissingCallback,
    SerializationError,
    BackendError,
    /// Used to relay FFI backend error code to the interface.
    Other(i32),
}

#[cfg(any(feature = "backend-ffi", feature = "ffi"))]
impl ErrorCode {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Self::Success => 0,
            Self::BufferTooSmall => 1,
            Self::MissingCallback => 2,
            Self::SerializationError => 3,
            Self::BackendError => 4,
            Self::Other(code) => *code,
        }
    }
}
