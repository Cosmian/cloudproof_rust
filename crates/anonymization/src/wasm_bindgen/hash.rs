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
    pub fn apply(&self, data: &[u8]) -> Result<String, JsValue> {
        Ok(wasm_unwrap!(
            self.0.apply(data),
            "Error applying hash method"
        ))
    }
}
