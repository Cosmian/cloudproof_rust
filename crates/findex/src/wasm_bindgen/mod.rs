//! Defines the WASM interface for Findex.

macro_rules! wasm_unwrap {
    ($res:expr, $msg:literal) => {
        $res.map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}: {e:?}", $msg)))?
    };
    ($res:expr, $msg:expr) => {
        $res.map_err(|e| wasm_bindgen::JsValue::from_str($expr.as_str()))?
    };
}

pub mod api;
pub mod core;
