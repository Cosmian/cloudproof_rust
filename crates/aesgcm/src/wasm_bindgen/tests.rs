use cloudproof_cover_crypt::reexport::crypto_core::Aes256Gcm;
use wasm_bindgen_test::wasm_bindgen_test;

use crate::wasm_bindgen::aesgcm::{webassembly_aes256gcm_decrypt, webassembly_aes256gcm_encrypt};

#[wasm_bindgen_test]
fn test_encrypt_decrypt() {
    let key = [42_u8; Aes256Gcm::KEY_LENGTH];
    let nonce = [42_u8; Aes256Gcm::NONCE_LENGTH];
    let authentication_data = vec![0_u8; 1024];
    let plaintext = b"plaintext";
    let ciphertext = webassembly_aes256gcm_encrypt(
        plaintext.to_vec(),
        key.to_vec(),
        nonce.to_vec(),
        authentication_data.to_vec(),
    )
    .unwrap();
    let cleartext = webassembly_aes256gcm_decrypt(
        ciphertext.to_vec(),
        key.to_vec(),
        nonce.to_vec(),
        authentication_data.to_vec(),
    )
    .unwrap();
    assert_eq!(plaintext.to_vec(), cleartext.to_vec());
}
