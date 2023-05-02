macro_rules! datestring_to_timestamp {
    ($date_str:expr) => {
        match DateTime::parse_from_rfc3339($date_str) {
            Ok(date) => Ok(date.with_timezone(&Utc).timestamp()),
            Err(e) => Err(e),
        }
    };
}

macro_rules! timestamp_to_datestring {
    ($noisy_date_unix:expr, $date_str:expr) => {
        match Utc.timestamp_opt($noisy_date_unix, 0) {
            chrono::LocalResult::None => Err(ano_error!(
                "Could not apply method on date `{}`.",
                $date_str
            )),
            chrono::LocalResult::Single(date) => Ok(date.to_rfc3339()),
            chrono::LocalResult::Ambiguous(_, _) => Err(ano_error!(
                "Applying method on date `{}` lead to ambiguous result.",
                $date_str
            )),
        }
    };
}

pub mod error;
pub use error::AnoError;

mod hash;
pub use hash::{HashMethod, Hasher};

mod noise;
pub use noise::{Laplace, NoiseGenerator, NoiseMethod};

mod word;
pub use word::{WordMasker, WordPatternMasker, WordTokenizer};

mod number;
pub use number::{DateAggregator, NumberAggregator, NumberScaler};

#[cfg(test)]
mod tests;
