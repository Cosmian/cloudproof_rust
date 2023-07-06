use cloudproof_cover_crypt::reexport::crypto_core::{FixedSizeCBytes, X25519PublicKey};
use wasm_bindgen_test::wasm_bindgen_test;

use super::ecies::webassembly_ecies_decrypt;
use crate::wasm_bindgen::ecies::{webassembly_ecies_encrypt, webassembly_ecies_generate_key_pair};

#[wasm_bindgen_test]
fn test_encrypt_decrypt() {
    let key_pair = webassembly_ecies_generate_key_pair().unwrap();
    let public_key = key_pair.to_vec()[0..X25519PublicKey::LENGTH].to_vec();
    let private_key = key_pair.to_vec()[X25519PublicKey::LENGTH..].to_vec();

    let plaintext = b"plaintext";
    let authenticated_data = b"authenticated_data";

    let ciphertext =
        webassembly_ecies_encrypt(plaintext.to_vec(), public_key, authenticated_data.to_vec())
            .unwrap();
    let cleartext = webassembly_ecies_decrypt(
        ciphertext.to_vec(),
        private_key,
        authenticated_data.to_vec(),
    )
    .unwrap();
    assert_eq!(plaintext.to_vec(), cleartext.to_vec());
}
