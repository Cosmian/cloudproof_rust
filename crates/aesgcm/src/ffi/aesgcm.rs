use std::ffi::{c_char, c_int, c_uchar};

use cosmian_ffi_utils::{ffi_read_bytes, ffi_unwrap, ffi_write_bytes};

use crate::core::{ReExposedAesGcm, KEY_LENGTH, NONCE_LENGTH};

unsafe extern "C" fn aesgcm(
    output_ptr: *mut c_uchar,
    output_len: *mut c_int,
    input_data_ptr: *const c_char,
    input_data_len: c_int,
    key_ptr: *const c_char,
    key_len: c_int,
    nonce_ptr: *const c_char,
    nonce_len: c_int,
    encrypt_flag: bool,
) -> c_int {
    let input_data_bytes = ffi_read_bytes!("input_data", input_data_ptr, input_data_len);
    let key_bytes = ffi_read_bytes!("key", key_ptr, key_len);
    let key: [u8; KEY_LENGTH] = ffi_unwrap!(
        key_bytes.try_into(),
        "AESGCM invalid key length, expected {KEY_LENGTH:?}"
    );
    let nonce_bytes = ffi_read_bytes!("nonce", nonce_ptr, nonce_len);
    let nonce: [u8; NONCE_LENGTH] = ffi_unwrap!(
        nonce_bytes.try_into(),
        "AESGCM invalid nonce length, expected {NONCE_LENGTH}"
    );

    let aesgcm = ffi_unwrap!(
        ReExposedAesGcm::instantiate(&key, &nonce),
        "Cannot create AESGCM cipher instance"
    );
    let output = if encrypt_flag {
        ffi_unwrap!(aesgcm.encrypt(input_data_bytes), "AESGCM encrypt error")
    } else {
        ffi_unwrap!(aesgcm.decrypt(input_data_bytes), "AESGCM decrypt error")
    };

    ffi_write_bytes!("output_ptr", &output, output_ptr, output_len);

    0
}

#[no_mangle]
pub unsafe extern "C" fn h_aesgcm_encrypt(
    output_ptr: *mut c_uchar,
    output_len: *mut c_int,
    plaintext_ptr: *const c_char,
    plaintext_len: c_int,
    key_ptr: *const c_char,
    key_len: c_int,
    nonce_ptr: *const c_char,
    nonce_len: c_int,
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
        true,
    )
}

#[no_mangle]
pub unsafe extern "C" fn h_aesgcm_decrypt(
    output_ptr: *mut c_uchar,
    output_len: *mut c_int,
    ciphertext_ptr: *const c_char,
    ciphertext_len: c_int,
    key_ptr: *const c_char,
    key_len: c_int,
    nonce_ptr: *const c_char,
    nonce_len: c_int,
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
        false,
    )
}
