macro_rules! wasm_unwrap {
    ($res:expr, $msg:literal) => {
        $res.map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}: {e:?}", $msg)))?
    };
}

use wasm_bindgen::prelude::*;

pub mod abe_policy;
pub mod generate_cc_keys;
pub mod hybrid_cc_aes;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    fn alert(s: &str);
}

#[cfg(test)]
mod tests;
