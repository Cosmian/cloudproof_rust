use pyo3::prelude::*;

use crate::core::NoiseGenerator as NoiseGeneratorRust;

#[pyclass]
pub struct NoiseGenerator(NoiseGeneratorRust<f64>);

#[pymethods]
impl NoiseGenerator {
    #[staticmethod]
    pub fn new_with_parameters(method_name: &str, mean: f64, std_dev: f64) -> PyResult<Self> {
        Ok(Self(pyo3_unwrap!(
            NoiseGeneratorRust::<f64>::new_with_parameters(method_name, mean, std_dev),
            "Error initializing noise"
        )))
    }

    #[staticmethod]
    pub fn new_date_with_parameters(
        method_name: &str,
        mean: f64,
        std_dev: f64,
        time_unit: &str,
    ) -> PyResult<Self> {
        Ok(Self(pyo3_unwrap!(
            NoiseGeneratorRust::<f64>::new_date_with_parameters(
                method_name,
                mean,
                std_dev,
                time_unit
            ),
            "Error initializing noise"
        )))
    }

    #[staticmethod]
    pub fn new_with_bounds(method_name: &str, min_bound: f64, max_bound: f64) -> PyResult<Self> {
        Ok(Self(pyo3_unwrap!(
            NoiseGeneratorRust::<f64>::new_with_bounds(method_name, min_bound, max_bound),
            "Error initializing noise"
        )))
    }

    pub fn apply_on_float(&self, data: f64) -> PyResult<f64> {
        Ok(pyo3_unwrap!(
            self.0.apply_on_float(data),
            "Error applying noise"
        ))
    }

    pub fn apply_on_int(&self, data: i64) -> PyResult<i64> {
        Ok(pyo3_unwrap!(
            self.0.apply_on_int(data),
            "Error applying noise"
        ))
    }

    pub fn apply_on_date(&self, date: &str) -> PyResult<String> {
        Ok(pyo3_unwrap!(
            self.0.apply_on_date(date),
            "Error applying noise"
        ))
    }
}
