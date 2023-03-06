//! Defines the FFI interface for Findex.

use ::core::{fmt::Display, num::TryFromIntError};

use crate::ser_de::SerializableSetError;

/// Maximum number of bytes used by a LEB128 encoding.
const LEB128_MAXIMUM_ENCODED_BYTES_NUMBER: usize = 8;

/// Limit on the recursion to use when none is provided.
// TODO (TBZ): is this parameter really necessary? It is used when the
// `max_depth` parameter given is less than 0 => shouldn't an error be returned
// instead ?
pub const MAX_DEPTH: usize = 100; // 100 should always be enough

#[repr(i32)]
#[derive(Debug)]
/// Callbacks return error codes, right now only 0 and 1 are specified.
/// Other error codes will be forwarded to the client as a response to
/// the main call error code so that the client can report some custom
/// callbacks errors (for example the Flutter lib is using 42 to report
/// an exception during a callback, save this exception and re-report this
/// exception at the end of the main call if the response is 42).
pub enum ErrorCode {
    Success = 0,

    /// <https://github.com/Cosmian/findex/issues/14>
    /// We use 1 here because we used to always retry in case of non-zero error
    /// code. We may want to change this in future major release (reserve 1
    /// for error and specify another error code for asking for a bigger
    /// buffer).
    BufferTooSmall = 1,

    MissingCallback = 2,

    SerializationError = 3,
}

macro_rules! to_error_with_code {
    ($expr:expr, $code:expr) => {
        $expr.map_err(|e| FindexFfiError::CallbackErrorCode {
            name: e.to_string(),
            code: $code as i32,
        })?
    };
}

#[derive(Debug)]
pub enum FindexFfiError {
    ConversionError(TryFromIntError),
    CallbackErrorCode { name: String, code: i32 },
}

impl From<TryFromIntError> for FindexFfiError {
    fn from(e: TryFromIntError) -> Self {
        Self::ConversionError(e)
    }
}

impl From<SerializableSetError> for FindexFfiError {
    fn from(value: SerializableSetError) -> Self {
        Self::CallbackErrorCode {
            name: format!("{value}"),
            code: ErrorCode::SerializationError as i32,
        }
    }
}

impl Display for FindexFfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConversionError(err) => write!(f, "{err}"),
            Self::CallbackErrorCode { name, code } => {
                write!(f, "callback returned with error code {code:?}: {name}")
            }
        }
    }
}

impl std::error::Error for FindexFfiError {}

impl cosmian_findex::CallbackError for FindexFfiError {}

pub mod api;
pub mod core;
