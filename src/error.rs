use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnoError {
    #[error("Anonymisation error: {0}")]
    Generic(String),
    #[error("FPE error: {0}")]
    FPE(String),
    #[error("Invalid key size {0}, expected: {1}")]
    KeySize(usize, usize),
    #[error("Conversion error: {0}")]
    ConversionError(String),
}

impl From<std::num::TryFromIntError> for AnoError {
    fn from(value: std::num::TryFromIntError) -> Self {
        AnoError::ConversionError(value.to_string())
    }
}

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! ano_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::AnoError::Generic($msg.to_owned()));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::AnoError::Generic(format!($fmt, $($arg)*)));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! ano_error {
    ($msg:literal $(,)?) => {
        $crate::error::AnoError::Generic($msg.to_owned())
    };
    ($err:expr $(,)?) => ({
        $crate::error::AnoError::Generic($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::AnoError::Generic(format!($fmt, $($arg)*))
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! ano_bail {
    ($msg:literal $(,)?) => {
        return ::core::result::Result::Err($crate::error::AnoError::Generic($msg.to_owned()))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::error::AnoError::Generic(format!($fmt, $($arg)*)))
    };
}
