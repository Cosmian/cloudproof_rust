//! Implementations of Findex Entry Table and Chain Table backends using
//! different database technologies.

mod callback_prefix;
mod error;

#[cfg(feature = "backend-cloud")]
pub mod cloud;

#[cfg(any(
    feature = "backend-wasm",
    feature = "backend-python",
    feature = "backend-ffi",
))]
pub mod custom;

#[cfg(feature = "backend-redis")]
pub mod redis;

#[cfg(feature = "backend-sqlite")]
pub mod sqlite;

#[cfg(test)]
mod tests;

#[cfg(any(
    feature = "backend-ffi",
    feature = "backend-cloud",
    feature = "backend-wasm"
))]
pub use callback_prefix::CallbackPrefix;
pub use error::BackendError;

/// The backend prefix is used in serialization to identify the targeted
/// backend.
pub enum BackendPrefix {
    Sqlite,
    Redis,
    Cloud,
    Ffi,
    Wasm,
    Python,
}

impl From<&BackendPrefix> for u8 {
    fn from(prefix: &BackendPrefix) -> Self {
        match prefix {
            BackendPrefix::Sqlite => 0,
            BackendPrefix::Redis => 1,
            BackendPrefix::Cloud => 2,
            BackendPrefix::Ffi => 3,
            BackendPrefix::Wasm => 4,
            BackendPrefix::Python => 5,
        }
    }
}

impl TryFrom<u8> for BackendPrefix {
    type Error = BackendError;

    fn try_from(prefix: u8) -> Result<Self, Self::Error> {
        match prefix {
            0 => Ok(Self::Sqlite),
            1 => Ok(Self::Redis),
            2 => Ok(Self::Cloud),
            3 => Ok(Self::Ffi),
            4 => Ok(Self::Wasm),
            5 => Ok(Self::Python),
            _ => Err(BackendError::Serialization(format!(
                "unknown backend prefix {prefix}"
            ))),
        }
    }
}
