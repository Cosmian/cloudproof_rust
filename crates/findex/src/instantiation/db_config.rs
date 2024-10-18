use reqwest::Client;

#[cfg(feature = "ffi")]
use crate::db_interfaces::custom::ffi::FfiCallbacks;
#[cfg(feature = "python")]
use crate::db_interfaces::custom::python::PythonCallbacks;
#[cfg(feature = "wasm")]
use crate::db_interfaces::custom::wasm::WasmCallbacks;
#[cfg(feature = "findex-cloud")]
use crate::db_interfaces::rest::AuthorizationToken;

/// Contains all parameters needed to instantiate the corresponding interfaces.
///
/// Inner parameters go by pair. The first ones are used to instantiate the
/// Entry Table while the second ones are used to instantiate the Chain Table.
#[derive(Clone)]
pub enum Configuration {
    /// Findex Cloud DB interface requires an authorization token and a server
    /// URL for the Entry and the Chain tables.
    #[cfg(feature = "findex-cloud")]
    FindexCloud(AuthorizationToken, String, String),

    /// REST DB interface requires an authorization token and a server URL for
    /// the Entry and the Chain tables.
    #[cfg(feature = "rest-interface")]
    Rest(Client, String, String),

    /// FFI DB interface requests FFI functions corresponding to the APIs used
    /// by the Entry/Chain tables.
    #[cfg(feature = "ffi")]
    Ffi(FfiCallbacks, FfiCallbacks),

    /// Python DB interface requests Python functions corresponding to the APIs
    /// used by the Entry/Chain tables.
    #[cfg(feature = "python")]
    Python(PythonCallbacks, PythonCallbacks),

    /// `SQLite` DB interface requests a valid
    /// [`Connection`](rusqlite::Connection) pointing to valid Entry/Chain
    /// tables.
    #[cfg(feature = "sqlite-interface")]
    Sqlite(String, String),

    /// Redis DB interface requests an URL to a valid instance.
    #[cfg(feature = "redis-interface")]
    Redis(String, String),

    /// WASM DB interface requests WASM functions corresponding to the APIs used
    /// by the Entry/Chain tables.
    #[cfg(feature = "wasm")]
    Wasm(WasmCallbacks, WasmCallbacks),
}
