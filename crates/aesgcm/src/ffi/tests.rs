use std::ffi::{c_char, c_int};

use cloudproof_cover_crypt::reexport::crypto_core::Aes256Gcm;
use cosmian_ffi_utils::error::get_last_error;

use super::aesgcm::{h_aesgcm_decrypt, h_aesgcm_encrypt};

#[test]
fn encrypt_decrypt() {
    let key = [42_u8; Aes256Gcm::KEY_LENGTH];
    let authenticated_data = [42_u8; Aes256Gcm::NONCE_LENGTH];
    let plaintext = b"plaintext";

    let key_ptr = key.as_ptr().cast();
    let key_len = key.len() as c_int;
    let authenticated_data_ptr = authenticated_data.as_ptr().cast();
    let authenticated_data_len = authenticated_data.len() as c_int;
    let plaintext_ptr = plaintext.as_ptr().cast();
    let plaintext_len = plaintext.len() as c_int;

    // FFI encrypt output
    let mut ciphertext_bytes =
        vec![0u8; plaintext.len() + Aes256Gcm::NONCE_LENGTH + Aes256Gcm::MAC_LENGTH];
    let ciphertext_ptr = ciphertext_bytes.as_mut_ptr().cast();
    let mut ciphertext_len = ciphertext_bytes.len() as c_int;

    // FFI decrypt output
    let mut cleartext_bytes = vec![0u8; ciphertext_len as usize];
    let cleartext_ptr = cleartext_bytes.as_mut_ptr().cast();
    let mut cleartext_len = cleartext_bytes.len() as c_int;

    unsafe {
        //
        // ENCRYPT
        //
        let ret = h_aesgcm_encrypt(
            ciphertext_ptr,
            &mut ciphertext_len,
            plaintext_ptr,
            plaintext_len,
            key_ptr,
            key_len,
            authenticated_data_ptr,
            authenticated_data_len,
        );
        assert!(
            0 == ret,
            "AESGCM FFI encryption failed. Exit with error: {ret}, error message: {:?}",
            get_last_error()
        );

        //
        // DECRYPT
        //
        let ret = h_aesgcm_decrypt(
            cleartext_ptr,
            &mut cleartext_len,
            ciphertext_ptr as *const c_char,
            ciphertext_len,
            key_ptr,
            key_len,
            authenticated_data_ptr,
            authenticated_data_len,
        );
        assert!(
            0 == ret,
            "AESGCM FFI decryption failed. Exit with error: {ret}, error message: {:?}",
            get_last_error()
        );

        let cleartext_bytes = std::slice::from_raw_parts(cleartext_ptr, cleartext_len as usize);
        assert_eq!(plaintext.to_vec(), cleartext_bytes.to_vec());
    }
}
