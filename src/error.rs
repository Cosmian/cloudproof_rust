use core::fmt::Display;

#[derive(Debug)]
pub enum AnoError {
    Generic(String),
    FPE(String),
    KeySize(usize, usize),
    ConversionError(String),
}

impl From<std::num::TryFromIntError> for AnoError {
    fn from(value: std::num::TryFromIntError) -> Self {
        AnoError::ConversionError(value.to_string())
    }
}

impl Display for AnoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnoError::Generic(err) => write!(f, "Anonymisation error: {err}"),
            AnoError::FPE(err) => write!(f, "FPE error: {err}"),
            AnoError::KeySize(given, expected) => {
                write!(f, "Invalid key size {given}, expected: {expected}")
            }
            AnoError::ConversionError(err) => write!(f, "Conversion error: {err}"),
        }
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
