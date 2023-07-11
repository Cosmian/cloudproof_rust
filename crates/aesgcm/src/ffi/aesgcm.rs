use std::ffi::{c_char, c_int, c_uchar};

use cloudproof_cover_crypt::reexport::crypto_core::Aes256Gcm;
use cosmian_ffi_utils::{ffi_read_bytes, ffi_unwrap, ffi_write_bytes};

use crate::{decrypt, encrypt};

unsafe extern "C" fn aesgcm(
    output_ptr: *mut c_uchar,
    output_len: *mut c_int,
    input_data_ptr: *const c_char,
    input_data_len: c_int,
    key_ptr: *const c_char,
    key_len: c_int,
    nonce_ptr: *const c_char,
    nonce_len: c_int,
    authenticated_data_ptr: *const c_char,
    authenticated_data_len: c_int,
    encrypt_flag: bool,
) -> c_int {
    let input_data_bytes = ffi_read_bytes!("input_data", input_data_ptr, input_data_len);
    let key_bytes = ffi_read_bytes!("key", key_ptr, key_len);
    let key: [u8; Aes256Gcm::KEY_LENGTH] = ffi_unwrap!(
        key_bytes.try_into(),
        format!(
            "AESGCM invalid key length, expected {}",
            Aes256Gcm::KEY_LENGTH
        )
    );
    let nonce_bytes = ffi_read_bytes!("nonce", nonce_ptr, nonce_len);
    let nonce: [u8; Aes256Gcm::NONCE_LENGTH] = ffi_unwrap!(
        nonce_bytes.try_into(),
        format!(
            "AESGCM invalid nonce length, expected {}",
            Aes256Gcm::NONCE_LENGTH
        )
    );
    let authenticated_data = ffi_read_bytes!(
        "authenticated_data",
        authenticated_data_ptr,
        authenticated_data_len
    );
    let output = if encrypt_flag {
        ffi_unwrap!(
            encrypt(key, nonce, input_data_bytes, authenticated_data),
            "AESGCM encrypt error"
        )
    } else {
        ffi_unwrap!(
            decrypt(key, nonce, input_data_bytes, authenticated_data),
            "AESGCM decrypt error"
        )
    };

    ffi_write_bytes!("output_ptr", &output, output_ptr, output_len);

    0
}

#[no_mangle]
pub unsafe extern "C" fn h_aes256gcm_encrypt(
    output_ptr: *mut c_uchar,
    output_len: *mut c_int,
    plaintext_ptr: *const c_char,
    plaintext_len: c_int,
    key_ptr: *const c_char,
    key_len: c_int,
    nonce_ptr: *const c_char,
    nonce_len: c_int,
    authenticated_data_ptr: *const c_char,
    authenticated_data_len: c_int,
) -> c_int {
    aesgcm(
        output_ptr,
        output_len,
        plaintext_ptr,
        plaintext_len,
        key_ptr,
        key_len,
        nonce_ptr,
        nonce_len,
        authenticated_data_ptr,
        authenticated_data_len,
        true,
    )
}

#[no_mangle]
pub unsafe extern "C" fn h_aes256gcm_decrypt(
    output_ptr: *mut c_uchar,
    output_len: *mut c_int,
    ciphertext_ptr: *const c_char,
    ciphertext_len: c_int,
    key_ptr: *const c_char,
    key_len: c_int,
    nonce_ptr: *const c_char,
    nonce_len: c_int,
    authenticated_data_ptr: *const c_char,
    authenticated_data_len: c_int,
) -> c_int {
    aesgcm(
        output_ptr,
        output_len,
        ciphertext_ptr,
        ciphertext_len,
        key_ptr,
        key_len,
        nonce_ptr,
        nonce_len,
        authenticated_data_ptr,
        authenticated_data_len,
        false,
    )
}
