use core::fmt::Display;

#[derive(Debug)]
pub enum AnoError {
    Generic(String),
    ConversionError(String),
}

impl From<std::convert::Infallible> for AnoError {
    fn from(value: std::convert::Infallible) -> Self {
        Self::ConversionError(value.to_string())
    }
}
impl From<chrono::ParseError> for AnoError {
    fn from(value: chrono::ParseError) -> Self {
        Self::ConversionError(value.to_string())
    }
}
impl From<rand_distr::NormalError> for AnoError {
    fn from(value: rand_distr::NormalError) -> Self {
        Self::Generic(value.to_string())
    }
}
impl From<argon2::Error> for AnoError {
    fn from(value: argon2::Error) -> Self {
        Self::Generic(value.to_string())
    }
}

impl Display for AnoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generic(err) => write!(f, "Anonymization error: {err}"),
            Self::ConversionError(err) => write!(f, "Conversion error: {err}"),
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
            return ::core::result::Result::Err($crate::core::error::AnoError::Generic($msg.to_owned()));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::core::error::AnoError::Generic(format!($fmt, $($arg)*)));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! ano_error {
    ($msg:literal $(,)?) => {
        AnoError::Generic($msg.to_owned())
    };
    ($err:expr $(,)?) => ({
        AnoError::Generic($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        AnoError::Generic(format!($fmt, $($arg)*))
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! ano_bail {
    ($msg:literal $(,)?) => {
        return ::core::result::Result::Err($crate::core::error::AnoError::Generic($msg.to_owned()))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::core::error::AnoError::Generic(format!($fmt, $($arg)*)))
    };
}
