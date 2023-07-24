use cosmian_ffi_utils::{ffi_read_bytes, ffi_unwrap, ffi_write_bytes};

use crate::{decrypt, encrypt};

unsafe extern "C" fn aesgcm(
    output_ptr: *mut u8,
    output_len: *mut i32,
    input_data_ptr: *const i8,
    input_data_len: i32,
    key_ptr: *const i8,
    key_len: i32,
    nonce_ptr: *const i8,
    nonce_len: i32,
    authenticated_data_ptr: *const i8,
    authenticated_data_len: i32,
    encrypt_flag: bool,
) -> i32 {
    let input_data_bytes = ffi_read_bytes!("input_data", input_data_ptr, input_data_len);
    let key_bytes = ffi_read_bytes!("key", key_ptr, key_len);
    let nonce_bytes = ffi_read_bytes!("nonce", nonce_ptr, nonce_len);
    let authenticated_data = ffi_read_bytes!(
        "authenticated_data",
        authenticated_data_ptr,
        authenticated_data_len
    );
    let output = if encrypt_flag {
        ffi_unwrap!(
            encrypt(key_bytes, nonce_bytes, input_data_bytes, authenticated_data),
            "AES-256 GCM encryption error"
        )
    } else {
        ffi_unwrap!(
            decrypt(key_bytes, nonce_bytes, input_data_bytes, authenticated_data),
            "AES-256 GCM decryption error"
        )
    };

    ffi_write_bytes!("output_ptr", &output, output_ptr, output_len);

    0
}

#[no_mangle]
pub unsafe extern "C" fn h_aes256gcm_encrypt(
    output_ptr: *mut u8,
    output_len: *mut i32,
    plaintext_ptr: *const i8,
    plaintext_len: i32,
    key_ptr: *const i8,
    key_len: i32,
    nonce_ptr: *const i8,
    nonce_len: i32,
    authenticated_data_ptr: *const i8,
    authenticated_data_len: i32,
) -> i32 {
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
    output_ptr: *mut u8,
    output_len: *mut i32,
    ciphertext_ptr: *const i8,
    ciphertext_len: i32,
    key_ptr: *const i8,
    key_len: i32,
    nonce_ptr: *const i8,
    nonce_len: i32,
    authenticated_data_ptr: *const i8,
    authenticated_data_len: i32,
) -> i32 {
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
