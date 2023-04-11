use chrono::{DateTime, TimeZone, Utc};
use rand_distr::num_traits::Pow;

use super::AnoError;
use crate::ano_error;

pub struct NumberAggregator {
    // TODO: change precision to a power of ten directly
    precision: u32,
}

impl NumberAggregator {
    #[must_use] pub fn new(precision: u32) -> Self {
        Self { precision }
    }

    #[must_use] pub fn apply_on_float(&self, data: f64) -> f64 {
        let y = f64::from(10.pow(self.precision));
        (data / y).round() * y
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
