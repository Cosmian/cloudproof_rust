use cloudproof_cover_crypt::reexport::crypto_core::Aes256Gcm;
use js_sys::Uint8Array;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::{decrypt, encrypt};

fn aes256gcm(
    input_data: Vec<u8>,
    key: Vec<u8>,
    nonce: Vec<u8>,
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
    // Copy the nonce bytes into a 12-byte array
    let n: [u8; Aes256Gcm::NONCE_LENGTH] = nonce.try_into().map_err(|_e| {
        JsValue::from_str(&format!(
            "AESGCM error: nonce length incorrect: expected {}",
            Aes256Gcm::NONCE_LENGTH
        ))
    })?;

    let output = if encrypt_flag {
        encrypt(k, n, &input_data, &authenticated_data)?
    } else {
        decrypt(k, n, &input_data, &authenticated_data)?
    };

    Ok(Uint8Array::from(output.as_slice()))
}

#[wasm_bindgen]
pub fn webassembly_aes256gcm_encrypt(
    plaintext: Vec<u8>,
    key: Vec<u8>,
    nonce: Vec<u8>,
    authenticated_data: Vec<u8>,
) -> Result<Uint8Array, JsValue> {
    aes256gcm(plaintext, key, nonce, authenticated_data, true)
}

#[wasm_bindgen]
pub fn webassembly_aes256gcm_decrypt(
    ciphertext: Vec<u8>,
    key: Vec<u8>,
    nonce: Vec<u8>,
    authenticated_data: Vec<u8>,
) -> Result<Uint8Array, JsValue> {
    aes256gcm(ciphertext, key, nonce, authenticated_data, false)
}
