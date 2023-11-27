use std::fmt::Display;

#[macro_use]
pub mod macros;

pub mod error;

/// Error code for FFI code.
#[derive(Debug, PartialEq, Eq)]
pub enum ErrorCode {
    Success,
    BufferTooSmall,          // The output buffer is too small
    MissingCallback,         // The callback needed does not exist
    Serialization,           // An error occurred during (de)serialization
    Backend,                 // The backend raised an error
    InvalidArgument(String), // Invalid argument passed
    Findex,                  // Findex call returned an error
    Managed,                 // FFI client managed the error
    Unknown(i32),            // An unknown code was retrieved
}

impl From<ErrorCode> for i32 {
    fn from(code: ErrorCode) -> Self {
        match code {
            ErrorCode::Success => 0,
            ErrorCode::BufferTooSmall => 1,
            ErrorCode::MissingCallback => 2,
            ErrorCode::Serialization => 3,
            ErrorCode::Backend => 4,
            ErrorCode::InvalidArgument(_) => 5,
            ErrorCode::Findex => 6,
            ErrorCode::Managed => 42,
            ErrorCode::Unknown(code) => code,
        }
    }
}

impl From<i32> for ErrorCode {
    fn from(value: i32) -> Self {
        // FFI code can only be a success, a managed error or an unknown error code.
        match value {
            0 => Self::Success,
            1 => Self::BufferTooSmall,
            42 => Self::Managed,
            code => Self::Unknown(code),
        }
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::BufferTooSmall => write!(f, "output buffer too small"),
            Self::MissingCallback => write!(f, "missing callback"),
            Self::Serialization => write!(f, "(de)serialization error"),
            Self::Backend => write!(f, "backend error"),
            Self::InvalidArgument(name) => write!(f, "invalid argument {name}"),
            Self::Findex => write!(f, "findex call returned with error"),
            Self::Managed => write!(f, "managed"),
            Self::Unknown(code) => write!(f, "unknown code ({code})"),
        }
    }
}
