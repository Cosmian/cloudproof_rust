use chrono::{DateTime, TimeZone, Utc};
use cosmian_crypto_core::CsRng;
use rand::SeedableRng;
use rand_distr::{Distribution, StandardNormal, Uniform};

use super::AnoError;
use crate::ano_error;

pub struct NumberAggregator {
    precision: f64,
}

impl NumberAggregator {
    #[must_use] pub fn new(precision: f64) -> Self {
        Self { precision }
    }

    #[must_use] pub fn apply_on_float(&self, data: f64) -> f64 {
        (data / self.precision).round() * self.precision
    }

    #[must_use] pub fn apply_on_int(&self, data: i64) -> i64 {
        self.apply_on_float(data as f64) as i64
    }

    pub fn apply_on_date(&self, date_str: &str) -> Result<String, AnoError> {
        let date_unix = DateTime::parse_from_rfc3339(date_str)?
            .with_timezone(&Utc)
            .timestamp();

        let rounded_date_unix = self.apply_on_int(date_unix);

        match Utc.timestamp_opt(rounded_date_unix, 0) {
            chrono::LocalResult::None => {
                Err(ano_error!("Could not apply noise on date `{}`.", date_str))
            }
            chrono::LocalResult::Single(date) => Ok(date.to_rfc3339()),
            chrono::LocalResult::Ambiguous(_, _) => Err(ano_error!(
                "Rounding date `{}` lead to ambiguous result.",
                date_str
            )),
        }
    }
}

pub struct NumberScaler {
    mean: f64,
    std_deviation: f64,
    rand_uniform: f64,
    rand_normal: f64,
}

impl NumberScaler {
    #[must_use] pub fn new(mean: f64, std_deviation: f64) -> Self {
        let mut rng = CsRng::from_entropy();
        let rand_uniform = Uniform::new(1.0, 100.0).sample(&mut rng);
        let rand_normal = 100.0 * &StandardNormal.sample(&mut rng);

        Self {
            mean,
            std_deviation,
            rand_uniform,
            rand_normal,
        }
    }

    #[must_use] pub fn apply_on_float(&self, data: f64) -> f64 {
        let normalized_data = (data - self.mean) / self.std_deviation;
        normalized_data.mul_add(self.rand_uniform, self.rand_normal)
    }
}
