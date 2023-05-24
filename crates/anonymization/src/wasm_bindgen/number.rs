use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::core::{
    DateAggregator as DateAggregatorRust, NumberAggregator as NumberAggregatorRust,
    NumberScaler as NumberScalerRust, TimeUnit,
};

#[wasm_bindgen]
pub struct NumberAggregator(NumberAggregatorRust);

#[wasm_bindgen]
impl NumberAggregator {
    #[wasm_bindgen(constructor)]
    pub fn new(power_of_ten: i32) -> Result<NumberAggregator, JsValue> {
        Ok(Self(wasm_unwrap!(
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

#[wasm_bindgen]
pub struct DateAggregator(DateAggregatorRust);

#[wasm_bindgen]
impl DateAggregator {
    #[wasm_bindgen(constructor)]
    pub fn new(time_unit: &str) -> Result<DateAggregator, JsValue> {
        let time_unit_rust = wasm_unwrap!(
            TimeUnit::try_from(time_unit),
            "Error initializing DateAggregator"
        );
        Ok(Self(DateAggregatorRust::new(time_unit_rust)))
    }

    pub fn apply_on_date(&self, date_str: &str) -> Result<String, JsValue> {
        Ok(wasm_unwrap!(
            self.0.apply_on_date(date_str),
            "Error rounding date"
        ))
    }
}

#[wasm_bindgen]
pub struct NumberScaler(NumberScalerRust);

#[wasm_bindgen]
impl NumberScaler {
    #[wasm_bindgen(constructor)]
    pub fn new(mean: f64, std_deviation: f64, scale: f64, translate: f64) -> Self {
        Self(NumberScalerRust::new(mean, std_deviation, scale, translate))
    }

    pub fn apply_on_float(&self, data: f64) -> f64 {
        self.0.apply_on_float(data)
    }

    pub fn apply_on_int(&self, data: i64) -> i64 {
        self.0.apply_on_int(data)
    }
}
