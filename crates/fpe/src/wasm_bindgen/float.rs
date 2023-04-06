use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::core::{Float, KEY_LENGTH};

fn fpe(input: f64, key: Vec<u8>, tweak: Vec<u8>, encrypt_flag: bool) -> Result<f64, JsValue> {
    let k: [u8; KEY_LENGTH] = key.try_into().map_err(|_e| {
        JsValue::from_str(&format!(
            "FPE Float error: key length incorrect: expected {KEY_LENGTH}"
        ))
    })?;
    let flt = Float::instantiate()
        .map_err(|e| JsValue::from_str(&format!("FPE Float instantiation failed: {e:?}")))?;

    let result = if encrypt_flag {
        flt.encrypt(&k, &tweak, input)
    } else {
        flt.decrypt(&k, &tweak, input)
    };
    result.map_err(|e| JsValue::from_str(&format!("FPE Float encryption/decryption failed: {e:?}")))
}

#[wasm_bindgen]
pub fn webassembly_fpe_encrypt_float(
    input: f64,
    key: Vec<u8>,
    tweak: Vec<u8>,
) -> Result<f64, JsValue> {
    fpe(input, key, tweak, true)
}

#[wasm_bindgen]
pub fn webassembly_fpe_decrypt_float(
    input: f64,
    key: Vec<u8>,
    tweak: Vec<u8>,
) -> Result<f64, JsValue> {
    fpe(input, key, tweak, false)
}
