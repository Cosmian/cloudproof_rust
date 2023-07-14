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
    let output = if encrypt_flag {
        encrypt(&key, &nonce, &input_data, &authenticated_data)?
    } else {
        decrypt(&key, &nonce, &input_data, &authenticated_data)?
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
