/// Convert `LocalResult<DateTime>` to a date in RFC3339 format.
macro_rules! datetime_to_rfc3339 {
    ($date_time:expr, $original_date:expr) => {
        match $date_time {
            chrono::LocalResult::None => Err(ano_error!(
                "Could not apply method on date `{}`.",
                $original_date
            )),
            chrono::LocalResult::Single(date) => Ok(date.to_rfc3339()),
            chrono::LocalResult::Ambiguous(_, _) => Err(ano_error!(
                "Applying method on date `{}` lead to ambiguous result.",
                $original_date
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
