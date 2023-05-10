use pyo3::prelude::*;

use crate::core::{
    DateAggregator as DateAggregatorRust, NumberAggregator as NumberAggregatorRust,
    NumberScaler as NumberScalerRust,
};

#[pyclass]
pub struct NumberAggregator(NumberAggregatorRust);

#[pymethods]
impl NumberAggregator {
    #[new]
    pub fn new(power_of_ten: i32) -> PyResult<Self> {
        Ok(Self(pyo3_unwrap!(
            NumberAggregatorRust::new(power_of_ten),
            "Error initializing NumberAggregator"
        )))
    }

    pub fn apply_on_float(&self, data: f64) -> String {
        self.0.apply_on_float(data)
    }

    pub fn apply_on_int(&self, data: i64) -> String {
        self.0.apply_on_int(data)
    }
}

#[pyclass]
pub struct DateAggregator(DateAggregatorRust);

#[pymethods]
impl DateAggregator {
    #[new]
    pub fn new(time_unit: &str) -> Self {
        Self(DateAggregatorRust::new(time_unit))
    }

    pub fn apply_on_date(&self, date_str: &str) -> PyResult<String> {
        Ok(pyo3_unwrap!(
            self.0.apply_on_date(date_str),
            "Error rounding date"
        ))
    }
}

#[pyclass]
pub struct NumberScaler(NumberScalerRust);

#[pymethods]
impl NumberScaler {
    #[new]
    pub fn new(mean: f64, std_dev: f64, scale: f64, translation: f64) -> Self {
        Self(NumberScalerRust::new(mean, std_dev, scale, translation))
    }

    pub fn apply_on_float(&self, data: f64) -> f64 {
        self.0.apply_on_float(data)
    }

    pub fn apply_on_int(&self, data: i64) -> i64 {
        self.0.apply_on_int(data)
    }
}
