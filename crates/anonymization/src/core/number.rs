use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};
use cosmian_crypto_core::CsRng;
use rand::{Rng, SeedableRng};
use rand_distr::{num_traits::Pow, Distribution, StandardNormal, Uniform};

use super::AnoError;
use crate::ano_error;

pub struct NumberAggregator {
    power_of_ten: i32,
}

impl NumberAggregator {
    #[must_use]
    pub fn new(power_of_ten: i32) -> Self {
        Self { power_of_ten }
    }

    #[must_use]
    pub fn apply_on_float(&self, data: f64) -> String {
        if self.power_of_ten < 0 {
            return format!("{:.1$}", data, -self.power_of_ten as usize);
        }
        let r = 10f64.pow(self.power_of_ten);
        format!("{}", (data / r).round() * r)
    }

    #[must_use]
    pub fn apply_on_int(&self, data: i64) -> String {
        let r = 10f64.pow(self.power_of_ten);
        format!("{:.0}", (data as f64 / r).round() * r)
    }
}

pub struct DateAggregator {
    time_unit: String,
}

impl DateAggregator {
    #[must_use]
    pub fn new(time_unit: &str) -> Self {
        Self {
            time_unit: time_unit.to_string(),
        }
    }

    pub fn apply_on_date(&self, date_str: &str) -> Result<String, AnoError> {
        let date = DateTime::parse_from_rfc3339(date_str)?.with_timezone(&Utc);

        let (y, mo, d, h, mi, s) = match self.time_unit.as_str() {
            "Second" => Ok((
                date.year(),
                date.month(),
                date.day(),
                date.hour(),
                date.minute(),
                date.second(),
            )),
            "Minute" => Ok((
                date.year(),
                date.month(),
                date.day(),
                date.hour(),
                date.minute(),
                0,
            )),
            "Hour" => Ok((date.year(), date.month(), date.day(), date.hour(), 0, 0)),
            "Day" => Ok((date.year(), date.month(), date.day(), 0, 0, 0)),
            "Month" => Ok((date.year(), date.month(), 1, 0, 0, 0)),
            "Year" => Ok((date.year(), 1, 1, 0, 0, 0)),
            _ => Err(ano_error!("Unknown time unit {}", &self.time_unit)),
        }?;

        match Utc.with_ymd_and_hms(y, mo, d, h, mi, s) {
            chrono::LocalResult::None => Err(ano_error!("Could not round date `{}`.", date_str)),
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
    #[must_use]
    pub fn new(mean: f64, std_deviation: f64, scale: f64, translate: f64) -> Self {
        let mut rng = CsRng::from_entropy();
        let rand_uniform = scale * Uniform::new(0.0001, 1.0).sample(&mut rng);
        let rand_normal = translate * rng.sample::<f64, _>(StandardNormal);

        Self {
            mean,
            std_deviation,
            rand_uniform,
            rand_normal,
        }
    }

    #[must_use]
    pub fn apply_on_float(&self, data: f64) -> f64 {
        let normalized_data = (data - self.mean) / self.std_deviation;
        normalized_data.mul_add(self.rand_uniform, self.rand_normal)
    }

    #[must_use]
    pub fn apply_on_int(&self, data: i64) -> i64 {
        self.apply_on_float(data as f64) as i64
    }
}
