use js_sys::Uint8Array;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::core::{HashMethod, Hasher as HasherRust};

#[wasm_bindgen]
pub struct Hasher(HasherRust);

#[wasm_bindgen]
impl Hasher {
    #[wasm_bindgen(constructor)]
    pub fn new(hasher_method: &str, salt_opt: Option<Vec<u8>>) -> Result<Hasher, JsValue> {
        let method = wasm_unwrap!(
            HashMethod::new(hasher_method, salt_opt),
            "Error initializing the hasher"
        );
        Ok(Self(HasherRust::new(method)))
    }

    #[wasm_bindgen]
    pub fn apply_str(&self, data: &str) -> Result<String, JsValue> {
        Ok(wasm_unwrap!(
            self.0.apply_str(data),
            "Error applying hash method"
        ))
    }

    #[wasm_bindgen]
    pub fn apply_bytes(&self, data: &[u8]) -> Result<Uint8Array, JsValue> {
        let hash = wasm_unwrap!(self.0.apply_bytes(data), "Error applying hash method");
        Ok(Uint8Array::from(hash.to_vec().as_slice()))
    }
}
