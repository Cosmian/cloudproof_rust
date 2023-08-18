#[cfg(feature = "backend-cloud")]
use crate::backends::cloud::CloudParameters;
#[cfg(feature = "backend-ffi")]
use crate::backends::custom::ffi::FfiCallbacks;
#[cfg(feature = "backend-python")]
use crate::backends::custom::python::PythonCallbacks;
#[cfg(feature = "backend-wasm")]
use crate::backends::custom::wasm::WasmCallbacks;

/// Contains all parameters needed to instantiate the corresponding backends.
///
/// Inner parameters go by pair. The first ones are used to instantiate the
/// Entry Table while the second ones are used to instantiate the Chain Table.
pub enum BackendConfiguration {
    /// Cloud backends require valid
    /// [`CloudParameters`](super::cloud::CloudParameters)
    #[cfg(feature = "backend-cloud")]
    Cloud(CloudParameters, CloudParameters),

    /// FFI backends request FFI functions corresponding to the APIs used by the
    /// Entry/Chain tables.
    #[cfg(feature = "backend-ffi")]
    Ffi(FfiCallbacks, FfiCallbacks),

    /// Python backends request Python functions corresponding to the APIs used
    /// by the Entry/Chain tables.
    #[cfg(feature = "backend-python")]
    Python(PythonCallbacks, PythonCallbacks),

    /// SQLite backends request a valid [`Connection`](rusqlite::Connection)
    /// pointing to valid Entry/Chain tables.
    #[cfg(feature = "backend-sqlite")]
    Sqlite(String, String),

    /// Redis backends request an URL to a valid instance.
    #[cfg(feature = "backend-redis")]
    Redis(String, String),

    /// WASM backends request WASM functions corresponding to the APIs used by
    /// the Entry/Chain tables.
    #[cfg(feature = "backend-wasm")]
    Wasm(WasmCallbacks, WasmCallbacks),
}
