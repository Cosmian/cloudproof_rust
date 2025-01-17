macro_rules! wasm_unwrap {
    ($res:expr, $msg:literal) => {
        $res.map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}: {e:?}", $msg)))?
    };
}

mod abe_policy;
mod generate_cc_keys;
mod hybrid_cc_aes;

#[allow(dead_code)]
#[cfg(test)]
mod tests;
