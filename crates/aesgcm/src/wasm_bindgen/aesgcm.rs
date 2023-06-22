use js_sys::Uint8Array;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::core::{ReExposedAesGcm, KEY_LENGTH, NONCE_LENGTH};

fn aesgcm(
    input_data: Vec<u8>,
    key: Vec<u8>,
    nonce: Vec<u8>,
    encrypt_flag: bool,
) -> Result<Uint8Array, JsValue> {
    // Copy the key bytes into a 32-byte array
    let k: [u8; KEY_LENGTH] = key.try_into().map_err(|_e| {
        JsValue::from_str(&format!(
            "AESGCM error: key length incorrect: expected {KEY_LENGTH}"
        ))
    })?;
    // Copy the nonce bytes into a 12-byte array
    let n: [u8; NONCE_LENGTH] = nonce.try_into().map_err(|_e| {
        JsValue::from_str(&format!(
            "AESGCM error: nonce length incorrect: expected {NONCE_LENGTH}"
        ))
    })?;

    let aesgcm = ReExposedAesGcm::instantiate(&k, &n)?;
    let output = if encrypt_flag {
        aesgcm.encrypt(&input_data)?
    } else {
        aesgcm.decrypt(&input_data)?
    };

    Ok(Uint8Array::from(output.as_slice()))
}

#[wasm_bindgen]
pub fn webassembly_aesgcm_encrypt(
    plaintext: Vec<u8>,
    key: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<Uint8Array, JsValue> {
    aesgcm(plaintext, key, nonce, true)
}

#[wasm_bindgen]
pub fn webassembly_aesgcm_decrypt(
    ciphertext: Vec<u8>,
    key: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<Uint8Array, JsValue> {
    aesgcm(ciphertext, key, nonce, false)
}
