pub mod error;
pub use error::AnoError;

use crate::ano_error;

mod hash;
pub use hash::{HashMethod, Hasher};

mod noise;
pub use noise::{NoiseGenerator, NoiseMethod};

mod word;
pub use word::{WordMasker, WordPatternMasker, WordTokenizer};

mod number;
pub use number::{NumberAggregator, NumberScaler};

pub fn date_precision(time_unit: &str) -> Result<f64, AnoError> {
    match time_unit {
        "Second" => Ok(1.0),
        "Minute" => Ok(60.0),
        "Hour" => Ok(3600.0),
        "Day" => Ok(86400.0),
        "Month" => Ok(2_628_000.0),
        "Year" => Ok(31_536_000.0),
        _ => Err(ano_error!("Unknown time unit {}", time_unit)),
    }
}

#[cfg(test)]
mod tests;
