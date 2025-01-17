//! Implementations of Findex Entry Table and Chain Table backends using
//! different database technologies.

mod error;

#[cfg(any(feature = "findex-cloud", feature = "rest-interface"))]
pub mod rest;

#[cfg(any(feature = "wasm", feature = "python", feature = "ffi",))]
pub mod custom;

#[cfg(feature = "redis-interface")]
pub mod redis;

#[cfg(feature = "sqlite-interface")]
pub mod sqlite;

#[cfg(all(
    test,
    any(
        feature = "ffi",
        feature = "python",
        feature = "redis-interface",
        feature = "findex-cloud",
        feature = "rest-interface",
        feature = "sqlite-interface",
        feature = "wasm",
    )
))]
mod tests;

pub use error::DbInterfaceError;

/// The backend prefix is used in serialization to identify the targeted
/// backend.
pub enum BackendPrefix {
    Sqlite,
    Redis,
    Rest,
    Ffi,
    Wasm,
    Python,
}

impl From<&BackendPrefix> for u8 {
    fn from(prefix: &BackendPrefix) -> Self {
        match prefix {
            BackendPrefix::Sqlite => 0,
            BackendPrefix::Redis => 1,
            BackendPrefix::Rest => 2,
            BackendPrefix::Ffi => 3,
            BackendPrefix::Wasm => 4,
            BackendPrefix::Python => 5,
        }
    }
}

impl TryFrom<u8> for BackendPrefix {
    type Error = DbInterfaceError;

    fn try_from(prefix: u8) -> Result<Self, Self::Error> {
        match prefix {
            0 => Ok(Self::Sqlite),
            1 => Ok(Self::Redis),
            2 => Ok(Self::Rest),
            3 => Ok(Self::Ffi),
            4 => Ok(Self::Wasm),
            5 => Ok(Self::Python),
            _ => Err(DbInterfaceError::Serialization(format!(
                "unknown backend prefix {prefix}"
            ))),
        }
    }
}
