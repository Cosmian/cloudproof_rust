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
    Encryption,              // Encryption error
    Decryption,              // Decryption error
    Covercrypt,              // Covercrypt call returned an error
    CovercryptPolicy,        // Error during Covercrypt Policy operation
    Managed,                 // FFI client managed the error
    Tokio,                   // Tokio runtime error
    Fpe,                     // Format Preserving Encryption error
    Ecies,                   // Ecies error
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
            ErrorCode::Encryption => 7,
            ErrorCode::Decryption => 8,
            ErrorCode::Covercrypt => 9,
            ErrorCode::CovercryptPolicy => 10,
            ErrorCode::Tokio => 11,
            ErrorCode::Fpe => 12,
            ErrorCode::Ecies => 13,
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
            2 => Self::MissingCallback,
            3 => Self::Serialization,
            4 => Self::Backend,
            6 => Self::Findex,
            7 => Self::Encryption,
            8 => Self::Decryption,
            9 => Self::Covercrypt,
            10 => Self::CovercryptPolicy,
            11 => Self::Tokio,
            12 => Self::Fpe,
            13 => Self::Ecies,
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
            Self::Encryption => write!(f, "encryption error"),
            Self::Decryption => write!(f, "decryption error"),
            Self::Covercrypt => write!(f, "covercrypt call returned with error"),
            Self::CovercryptPolicy => write!(f, "covercrypt policy call returned with error"),
            Self::Tokio => write!(f, "tokio error"),
            Self::Fpe => write!(f, "format preserving encryption error"),
            Self::Ecies => write!(f, "ecies error"),
            Self::Managed => write!(f, "managed"),
            Self::Unknown(code) => write!(f, "unknown code ({code})"),
        }
    }
}
