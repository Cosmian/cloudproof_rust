use cloudproof_cover_crypt::reexport::crypto_core::{FixedSizeCBytes, X25519PublicKey};
use wasm_bindgen_test::wasm_bindgen_test;

use crate::wasm_bindgen::ecies::{
    webassembly_ecies_salsa_seal_box_decrypt, webassembly_ecies_salsa_seal_box_encrypt,
    webassembly_x25519_generate_key_pair,
};

#[wasm_bindgen_test]
fn test_encrypt_decrypt() {
    let key_pair = webassembly_x25519_generate_key_pair().unwrap();
    let public_key = key_pair.to_vec()[0..X25519PublicKey::LENGTH].to_vec();
    let private_key = key_pair.to_vec()[X25519PublicKey::LENGTH..].to_vec();

    let plaintext = b"plaintext";
    let authenticated_data = b"authenticated_data";

    let ciphertext = webassembly_ecies_salsa_seal_box_encrypt(
        plaintext.to_vec(),
        public_key,
        authenticated_data.to_vec(),
    )
    .unwrap();
    let cleartext = webassembly_ecies_salsa_seal_box_decrypt(
        ciphertext.to_vec(),
        private_key,
        authenticated_data.to_vec(),
    )
    .unwrap();
    assert_eq!(plaintext.to_vec(), cleartext.to_vec());
}
