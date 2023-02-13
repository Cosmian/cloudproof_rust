macro_rules! wasm_unwrap {
    ($expression: expr, $context: literal) => {
        $expression.map_err(|e| JsValue::from_str(&format!("{}: {e:?}", $context)))?
    };
}

pub mod abe_policy;
pub mod generate_cc_keys;
pub mod hybrid_cc_aes;

#[cfg(test)]
mod tests;
