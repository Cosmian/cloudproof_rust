//! Defines the FFI interface for Findex.

use std::num::TryFromIntError;

use ::core::fmt::Display;

use self::error::ToErrorCode;

#[repr(i32)]
#[derive(Debug)]
/// Callbacks return error codes, right now only 0 and 1 are specified.
/// Other error codes will be forwarded to the client as a response to
/// the main call error code so that the client can report some custom
/// callbacks errors (for example the Flutter lib is using 42 to report
/// an exception during a callback, save this exception and re-report this
/// exception at the end of the main call if the response is 42).
pub enum ErrorCode {
    Success,

    /// <https://github.com/Cosmian/findex/issues/14>
    /// We use 1 here because we used to always retry in case of non-zero error
    /// code. We may want to change this in future major release (reserve 1
    /// for error and specify another error code for asking for a bigger
    /// buffer).
    BufferTooSmall,

    MissingCallback,

    SerializationError,

    Other(i32),
}

impl ErrorCode {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Self::Success => 0,
            Self::BufferTooSmall => 1,
            Self::MissingCallback => 2,
            Self::SerializationError => 3,
            Self::Other(code) => *code,
        }
    }
}

macro_rules! wrapping_callback_ser_de_error_with_context {
    ($result:expr, $context:literal) => {
        $result.map_err(|e| FindexFfiError::WrappingCallbackSerDeError {
            context: $context.to_owned(),
            error: e.to_string(),
        })?
    };
    ($result:expr, $context:expr) => {
        $result.map_err(|e| FindexFfiError::WrappingCallbackSerDeError {
            context: $context,
            error: e.to_string(),
        })?
    };
}

#[derive(Debug)]
pub(crate) enum FindexFfiError {
    /// FFI use u32 as a base type for the callbacks (why?) but the input value
    /// is often a Rust `usize`. Even if these kind of errors should never
    /// happen in real code, we need a variant to encode these.
    IntConversionError(TryFromIntError),

    /// This error happen if the FFI callback return an invalid
    /// error code. We don't know what happen inside it (maybe an exception, the
    /// user cannot fetch its database, a user error…).
    UserCallbackErrorCode {
        callback_name: &'static str,
        code: i32,
    },

    /// Findex wrap the FFI callback inside it's own callback that manage the
    /// serialization/deserialization of the results.
    ///
    /// These operations can fail (if there is a bug inside our code or if the
    /// callbacks returns us invalid bytes) so we should return the maximum
    /// information to the user so it can fix it's implementation.
    WrappingCallbackSerDeError { context: String, error: String },

    /// It is here because instead of implementing one trait for each type of
    /// request (search/upsert/compact), we've created only one trait with
    /// `Option<Callback>` so we fail at runtime if one of the callback wasn't
    /// provided for one operation.
    ///
    /// We should check that all required
    /// callback are set in the upper function so this error should never
    /// happen.
    CallbackNotImplemented { callback_name: &'static str },
}

impl ToErrorCode for FindexFfiError {
    fn to_error_code(&self) -> i32 {
        match self {
            Self::IntConversionError(_) => 1,
            Self::UserCallbackErrorCode { code, .. } => *code,
            Self::WrappingCallbackSerDeError { .. } => ErrorCode::SerializationError.code(),
            Self::CallbackNotImplemented { .. } => ErrorCode::MissingCallback.code(),
        }
    }
}

impl From<TryFromIntError> for FindexFfiError {
    fn from(e: TryFromIntError) -> Self {
        Self::IntConversionError(e)
    }
}

impl Display for FindexFfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntConversionError(err) => write!(f, "{err}"),
            Self::UserCallbackErrorCode {
                callback_name,
                code,
            } => {
                write!(
                    f,
                    "your callback {callback_name} returned with error code {code}",
                )
            }
            Self::WrappingCallbackSerDeError { context, error } => {
                write!(f, "a serialization error occurred while {context}: {error}",)
            }
            Self::CallbackNotImplemented { callback_name } => {
                write!(f, "callback {callback_name} is not implemented",)
            }
        }
    }
}

impl std::error::Error for FindexFfiError {}

impl cosmian_findex::CallbackError for FindexFfiError {}

pub mod api;
pub mod core;
pub mod error;
#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests;
