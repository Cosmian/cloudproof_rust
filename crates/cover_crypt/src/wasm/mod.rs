macro_rules! wasm_unwrap {
    ($res:expr, $msg:literal) => {
        $res.map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}: {e:?}", $msg)))?
    };
}

pub mod abe_policy;
pub mod generate_cc_keys;
pub mod hybrid_cc_aes;

#[cfg(test)]
mod tests;
