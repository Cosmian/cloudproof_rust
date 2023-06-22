use wasm_bindgen_test::wasm_bindgen_test;

use crate::{
    core::{KEY_LENGTH, NONCE_LENGTH},
    wasm_bindgen::aesgcm::{webassembly_aesgcm_decrypt, webassembly_aesgcm_encrypt},
};

#[wasm_bindgen_test]
fn test_encrypt_decrypt() {
    let key = [42_u8; KEY_LENGTH];
    let nonce = [42_u8; NONCE_LENGTH];
    let plaintext = b"plaintext";
    let ciphertext =
        webassembly_aesgcm_encrypt(plaintext.to_vec(), key.to_vec(), nonce.to_vec()).unwrap();
    let cleartext =
        webassembly_aesgcm_decrypt(ciphertext.to_vec(), key.to_vec(), nonce.to_vec()).unwrap();
    assert_eq!(plaintext.to_vec(), cleartext.to_vec());
}
