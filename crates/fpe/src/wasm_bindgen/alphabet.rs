use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::get_alphabet;

fn fpe(
    input: &str,
    alphabet_id: &str,
    key: Vec<u8>,
    tweak: Vec<u8>,
    additional_chars: &str,
    encrypt_flag: bool,
) -> Result<String, JsValue> {
    let mut alphabet =
        get_alphabet(alphabet_id).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;

    alphabet.extend_with(additional_chars);

    let output = if encrypt_flag {
        alphabet.encrypt(&key, &tweak, input)
    } else {
        alphabet.decrypt(&key, &tweak, input)
    };
    output.map_err(|e| JsValue::from_str(&format!("{e:?}")))
}

#[wasm_bindgen]
pub fn webassembly_fpe_encrypt_alphabet(
    plaintext: &str,
    alphabet_id: &str,
    key: Vec<u8>,
    tweak: Vec<u8>,
    additional_chars: &str,
) -> Result<String, JsValue> {
    fpe(plaintext, alphabet_id, key, tweak, additional_chars, true)
}

#[wasm_bindgen]
pub fn webassembly_fpe_decrypt_alphabet(
    ciphertext: &str,
    alphabet_id: &str,
    key: Vec<u8>,
    tweak: Vec<u8>,
    additional_chars: &str,
) -> Result<String, JsValue> {
    fpe(ciphertext, alphabet_id, key, tweak, additional_chars, false)
}
