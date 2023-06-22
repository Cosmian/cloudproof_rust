use std::ffi::{c_char, c_int};

use cosmian_ffi_utils::error::get_last_error;

use super::aesgcm::{h_aesgcm_decrypt, h_aesgcm_encrypt};
use crate::core::{BLOCK_LENGTH, KEY_LENGTH, NONCE_LENGTH};

#[test]
fn encrypt_decrypt() {
    let key = [42_u8; KEY_LENGTH];
    let nonce = [42_u8; NONCE_LENGTH];
    let plaintext = b"plaintext";

    let key_ptr = key.as_ptr().cast();
    let key_len = key.len() as c_int;
    let nonce_ptr = nonce.as_ptr().cast();
    let nonce_len = nonce.len() as c_int;
    let plaintext_ptr = plaintext.as_ptr().cast();
    let plaintext_len = plaintext.len() as c_int;

    // FFI encrypt output
    let mut ciphertext_bytes = vec![0u8; plaintext.len() + BLOCK_LENGTH];
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
            nonce_ptr,
            nonce_len,
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
            nonce_ptr,
            nonce_len,
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
