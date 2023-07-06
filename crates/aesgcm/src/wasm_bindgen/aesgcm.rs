use cloudproof_cover_crypt::reexport::crypto_core::Aes256Gcm;
use js_sys::Uint8Array;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::{decrypt, encrypt};

fn aesgcm(
    input_data: Vec<u8>,
    key: Vec<u8>,
    authenticated_data: Vec<u8>,
    encrypt_flag: bool,
) -> Result<Uint8Array, JsValue> {
    // Copy the key bytes into a 32-byte array
    let k: [u8; Aes256Gcm::KEY_LENGTH] = key.try_into().map_err(|_e| {
        JsValue::from_str(&format!(
            "AESGCM error: key length incorrect: expected {}",
            Aes256Gcm::KEY_LENGTH
        ))
    })?;

    let output = if encrypt_flag {
        encrypt(k, &input_data, &authenticated_data)?
    } else {
        decrypt(k, &input_data, &authenticated_data)?
    };

    Ok(Uint8Array::from(output.as_slice()))
}

#[wasm_bindgen]
pub fn webassembly_aesgcm_encrypt(
    plaintext: Vec<u8>,
    key: Vec<u8>,
    authenticated_data: Vec<u8>,
) -> Result<Uint8Array, JsValue> {
    aesgcm(plaintext, key, authenticated_data, true)
}

#[wasm_bindgen]
pub fn webassembly_aesgcm_decrypt(
    ciphertext: Vec<u8>,
    key: Vec<u8>,
    authenticated_data: Vec<u8>,
) -> Result<Uint8Array, JsValue> {
    aesgcm(ciphertext, key, authenticated_data, false)
}
