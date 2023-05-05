macro_rules! wasm_unwrap {
    ($res:expr, $msg:literal) => {
        $res.map_err(|e| wasm_bindgen::JsValue::from_str(&format!("{}: {e:?}", $msg)))?
    };
}

mod hash;
mod noise;
mod number;
#[cfg(test)]
mod tests;
mod word;
