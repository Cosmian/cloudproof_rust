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
    pub fn new_with_bounds(method_name: &str, min_bound: f64, max_bound: f64) -> PyResult<Self> {
        Ok(Self(pyo3_unwrap!(
            NoiseGeneratorRust::<f64>::new_with_bounds(method_name, min_bound, max_bound),
            "Error initializing noise"
        )))
    }

    pub fn apply_on_float(&mut self, data: f64) -> PyResult<f64> {
        Ok(pyo3_unwrap!(
            self.0.apply_on_float(data),
            "Error applying noise"
        ))
    }

    pub fn apply_correlated_noise_on_floats(
        &mut self,
        data: Vec<f64>,
        factors: Vec<f64>,
    ) -> PyResult<Vec<f64>> {
        Ok(pyo3_unwrap!(
            self.0.apply_correlated_noise_on_floats(&data, &factors),
            "Error applying noise"
        ))
    }

    pub fn apply_on_int(&mut self, data: i64) -> PyResult<i64> {
        Ok(pyo3_unwrap!(
            self.0.apply_on_int(data),
            "Error applying noise"
        ))
    }

    pub fn apply_correlated_noise_on_ints(
        &mut self,
        data: Vec<i64>,
        factors: Vec<f64>,
    ) -> PyResult<Vec<i64>> {
        Ok(pyo3_unwrap!(
            self.0.apply_correlated_noise_on_ints(&data, &factors),
            "Error applying noise"
        ))
    }

    pub fn apply_on_date(&mut self, date: &str) -> PyResult<String> {
        Ok(pyo3_unwrap!(
            self.0.apply_on_date(date),
            "Error applying noise"
        ))
    }

    pub fn apply_correlated_noise_on_dates(
        &mut self,
        data: Vec<&str>,
        factors: Vec<f64>,
    ) -> PyResult<Vec<String>> {
        Ok(pyo3_unwrap!(
            self.0.apply_correlated_noise_on_dates(&data, &factors),
            "Error applying noise"
        ))
    }
}
