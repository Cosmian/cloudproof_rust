use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::core::NoiseGenerator as NoiseGeneratorRust;

#[wasm_bindgen]
pub struct NoiseGeneratorWithParameters(NoiseGeneratorRust<f64>);

#[wasm_bindgen]
impl NoiseGeneratorWithParameters {
    #[wasm_bindgen(constructor)]
    pub fn new(
        method_name: &str,
        mean: f64,
        std_dev: f64,
    ) -> Result<NoiseGeneratorWithParameters, JsValue> {
        Ok(Self(wasm_unwrap!(
            NoiseGeneratorRust::<f64>::new_with_parameters(method_name, mean, std_dev),
            "Error initializing noise with parameters"
        )))
    }
}

#[wasm_bindgen]
pub struct NoiseGeneratorWithBounds(NoiseGeneratorRust<f64>);

#[wasm_bindgen]
impl NoiseGeneratorWithBounds {
    #[wasm_bindgen(constructor)]
    pub fn new(
        method_name: &str,
        min_bound: f64,
        max_bound: f64,
    ) -> Result<NoiseGeneratorWithBounds, JsValue> {
        Ok(Self(wasm_unwrap!(
            NoiseGeneratorRust::<f64>::new_with_bounds(method_name, min_bound, max_bound),
            "Error initializing noise with bounds"
        )))
    }
}

macro_rules! impl_noise {
    ($type_name:ty) => {
        #[wasm_bindgen]
        impl $type_name {
            #[wasm_bindgen]
            pub fn apply_on_float(&self, data: f64) -> Result<f64, JsValue> {
                Ok(wasm_unwrap!(
                    self.0.apply_on_float(data),
                    "Error applying noise"
                ))
            }

            #[wasm_bindgen]
            pub fn apply_correlated_noise_on_floats(
                &self,
                data: Vec<f64>,
                factors: Vec<f64>,
            ) -> Result<Vec<f64>, JsValue> {
                Ok(wasm_unwrap!(
                    self.0.apply_correlated_noise_on_floats(&data, &factors),
                    "Error applying noise"
                ))
            }

            #[wasm_bindgen]
            pub fn apply_on_int(&self, data: i64) -> Result<i64, JsValue> {
                Ok(wasm_unwrap!(
                    self.0.apply_on_int(data),
                    "Error applying noise"
                ))
            }

            #[wasm_bindgen]
            pub fn apply_correlated_noise_on_ints(
                &self,
                data: Vec<i64>,
                factors: Vec<f64>,
            ) -> Result<Vec<i64>, JsValue> {
                Ok(wasm_unwrap!(
                    self.0.apply_correlated_noise_on_ints(&data, &factors),
                    "Error applying noise"
                ))
            }

            #[wasm_bindgen]
            pub fn apply_on_date(&self, date: &str) -> Result<String, JsValue> {
                Ok(wasm_unwrap!(
                    self.0.apply_on_date(date),
                    "Error applying noise"
                ))
            }

            #[wasm_bindgen]
            pub fn apply_correlated_noise_on_dates(
                &self,
                data: String,
                factors: Vec<f64>,
            ) -> Result<String, JsValue> {
                let data: Vec<&str> = data.split(';').map(|s| s.trim()).collect();
                let results = wasm_unwrap!(
                    self.0.apply_correlated_noise_on_dates(&data, &factors),
                    "Error applying noise"
                );
                Ok(results.join(";"))
            }
        }
    };
}

impl_noise!(NoiseGeneratorWithParameters);
impl_noise!(NoiseGeneratorWithBounds);
