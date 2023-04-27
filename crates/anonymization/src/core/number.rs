use chrono::{DateTime, Datelike, Timelike, Utc};
use rand_distr::num_traits::Pow;

use super::AnoError;
use crate::ano_error;

/// The `NumberAggregator` is a data anonymization technique used to round
/// sensitive measurements to the desired power of ten.
///
/// Example usage:
///
/// ```
/// use cloudproof_anonymization::core::NumberAggregator;
///
/// let num_agg = NumberAggregator::new(2);
/// let anonymized_float = num_agg.apply_on_float(1234.5678); // returns "1200"
/// let anonymized_int = num_agg.apply_on_int(56789); // returns "56800"
/// ```
pub struct NumberAggregator {
    power_of_ten_exponent: i32,
}

impl NumberAggregator {
    /// Creates a new instance of `NumberAggregator`.
    ///
    /// # Arguments
    ///
    /// * `power_of_ten_exponent` - The power of ten to round the numbers to.
    pub fn new(power_of_ten_exponent: i32) -> Result<Self, AnoError> {
        // exponent cannot be greater than 308(https://doc.rust-lang.org/std/primitive.f64.html#associatedconstant.MAX_10_EXP)
        if power_of_ten_exponent > f64::MAX_10_EXP {
            return Err(ano_error!(
                "Exponent must be lower than 308, given {}.",
                power_of_ten_exponent
            ));
        }
        Ok(Self {
            power_of_ten_exponent,
        })
    }

    /// Rounds a floating point number to the desired power of ten.
    ///
    /// # Arguments
    ///
    /// * `data` - The floating point number to round.
    ///
    /// # Returns
    ///
    /// A string representation of the rounded number.
    #[must_use]
    pub fn apply_on_float(&self, data: f64) -> String {
        if self.power_of_ten_exponent < 0 {
            return format!("{:.1$}", data, -self.power_of_ten_exponent as usize);
        }
        let r = 10f64.pow(self.power_of_ten_exponent);
        format!("{}", (data / r).round() * r)
    }

    /// Rounds an integer to the desired power of ten.
    ///
    /// # Arguments
    ///
    /// * `data` - The integer to round.
    ///
    /// # Returns
    ///
    /// A string representation of the rounded number.
    #[must_use]
    pub fn apply_on_int(&self, data: i64) -> String {
        let r = 10f64.pow(self.power_of_ten_exponent);
        format!("{:.0}", (data as f64 / r).round() * r)
    }
}

/// A data anonymization technique to round dates to the unit of time specified.
///
/// Example usage:
///
/// ```
/// use cloudproof_anonymization::core::DateAggregator;
///
/// let aggregator = DateAggregator::new("Hour");
/// let result = aggregator.apply_on_date("2022-04-28T14:30:00Z"); // returns "2022-04-28T14:00:00+00:00"
/// ```
pub struct DateAggregator {
    time_unit: String,
}

impl DateAggregator {
    /// Creates a new instance of `DateAggregator` with the provided time unit.
    ///
    /// # Arguments
    ///
    /// * `time_unit`: the unit of time to round the date to.
    #[must_use]
    pub fn new(time_unit: &str) -> Self {
        Self {
            time_unit: time_unit.to_string(),
        }
    }

    /// Applies the date rounding to the provided date string based on the unit
    /// of time.
    ///
    /// # Arguments
    ///
    /// * `date_str`: A string representing the date to be rounded.
    ///
    /// # Returns
    ///
    /// The rounded date in RFC 3339
    #[allow(deprecated)]
    pub fn apply_on_date(&self, date_str: &str) -> Result<String, AnoError> {
        // Parse the date string into a DateTime.
        let date = DateTime::parse_from_rfc3339(date_str)?.with_timezone(&Utc);

        let rounded_date = match self.time_unit.as_str() {
            "Second" => date.with_nanosecond(0).unwrap(),
            "Minute" => date.with_second(0).unwrap().with_nanosecond(0).unwrap(),
            "Hour" => date
                .with_minute(0)
                .unwrap()
                .with_second(0)
                .unwrap()
                .with_nanosecond(0)
                .unwrap(),
            "Day" => date.date().and_hms_opt(0, 0, 0).unwrap(),
            "Month" => date
                .date()
                .with_day(1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            "Year" => date
                .date()
                .with_month(1)
                .unwrap()
                .with_day(1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            _ => return Err(ano_error!("Unknown time unit {}", &self.time_unit)),
        };

        Ok(rounded_date.to_rfc3339())
    }
}

/// A data anonymization method that scales individual values while keeping the
/// overall distribution of the data.
pub struct NumberScaler {
    mean: f64,
    std_deviation: f64,
    scale: f64,
    translate: f64,
}

impl NumberScaler {
    /// Creates a new `NumberScaler` instance.
    ///
    /// # Arguments
    ///
    /// * `mean`: The mean of the data distribution.
    /// * `std_deviation`: The standard deviation of the data distribution.
    /// * `scale`: The scaling factor.
    /// * `translate`: The translation factor.
    #[must_use]
    pub fn new(mean: f64, std_deviation: f64, scale: f64, translate: f64) -> Self {
        Self {
            mean,
            std_deviation,
            scale,
            translate,
        }
    }

    /// Applies the scaling and translation on a floating-point number.
    ///
    /// # Arguments
    ///
    /// * `data`: A floating-point number to be scaled.
    ///
    /// # Returns
    ///
    /// The scaled value.
    #[must_use]
    pub fn apply_on_float(&self, data: f64) -> f64 {
        // Apply scaling and translation to the normalized data
        let normalized_data = (data - self.mean) / self.std_deviation;
        normalized_data.mul_add(self.scale, self.translate)
    }

    /// Applies the scaling and translation on an integer.
    ///
    /// # Arguments
    ///
    /// * `data`: An integer to be scaled.
    ///
    /// # Returns
    ///
    /// The scaled value as an integer.
    #[must_use]
    pub fn apply_on_int(&self, data: i64) -> i64 {
        self.apply_on_float(data as f64) as i64
    }
}
