use std::ffi::{c_char, c_int};

use cloudproof_cover_crypt::reexport::crypto_core::{
    FixedSizeCBytes, X25519PrivateKey, X25519PublicKey,
};
use cosmian_ffi_utils::error::get_last_error;

use super::ecies::{h_ecies_encrypt_get_overhead_size, h_ecies_generate_key_pair};
use crate::ffi::ecies::{h_ecies_decrypt, h_ecies_encrypt};

#[test]
fn encrypt_decrypt() {
    let plaintext = b"plaintext";
    let plaintext_ptr = plaintext.as_ptr().cast();
    let plaintext_len = plaintext.len() as c_int;

    let authenticated_data = b"authenticated_data";
    let authenticated_data_ptr = authenticated_data.as_ptr().cast();
    let authenticated_data_len = authenticated_data.len() as c_int;

    // FFI 'key generation' output
    let mut public_key_bytes = vec![0u8; X25519PublicKey::LENGTH];
    let public_key_ptr = public_key_bytes.as_mut_ptr().cast();
    let mut public_key_len = public_key_bytes.len() as c_int;
    let mut private_key_bytes = vec![0u8; X25519PrivateKey::LENGTH];
    let private_key_ptr = private_key_bytes.as_mut_ptr().cast();
    let mut private_key_len = private_key_bytes.len() as c_int;

    unsafe {
        let ret = h_ecies_generate_key_pair(
            public_key_ptr,
            &mut public_key_len,
            private_key_ptr,
            &mut private_key_len,
        );
        assert!(
            0 == ret,
            "ECIES FFI key pair generation failed. Exit with error: {ret}, error message: {:?}",
            get_last_error()
        );

        // FFI encrypt output
        let mut ciphertext_bytes = vec![0u8; plaintext.len() + h_ecies_encrypt_get_overhead_size()];
        let ciphertext_ptr = ciphertext_bytes.as_mut_ptr().cast();
        let mut ciphertext_len = ciphertext_bytes.len() as c_int;

        // FFI decrypt output
        let mut cleartext_bytes = vec![0u8; ciphertext_len as usize];
        let cleartext_ptr = cleartext_bytes.as_mut_ptr().cast();
        let mut cleartext_len = cleartext_bytes.len() as c_int;

        //
        // ENCRYPT
        //
        let ret = h_ecies_encrypt(
            ciphertext_ptr,
            &mut ciphertext_len,
            plaintext_ptr,
            plaintext_len,
            public_key_ptr as *const c_char,
            public_key_len,
            authenticated_data_ptr,
            authenticated_data_len,
        );
        assert!(
            0 == ret,
            "ECIES FFI encryption failed. Exit with error: {ret}, error message: {:?}",
            get_last_error()
        );

        //
        // DECRYPT
        //
        let ret = h_ecies_decrypt(
            cleartext_ptr,
            &mut cleartext_len,
            ciphertext_ptr as *const c_char,
            ciphertext_len,
            private_key_ptr as *const c_char,
            private_key_len,
            authenticated_data_ptr,
            authenticated_data_len,
        );
        assert!(
            0 == ret,
            "ECIES FFI decryption failed. Exit with error: {ret}, error message: {:?}",
            get_last_error()
        );

        let cleartext_bytes = std::slice::from_raw_parts(cleartext_ptr, cleartext_len as usize);
        assert_eq!(plaintext.to_vec(), cleartext_bytes.to_vec());
    }
}
