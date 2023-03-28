use std::ffi::{c_char, c_double, c_int};

use cosmian_ffi_utils::{ffi_read_bytes, ffi_unwrap};

use crate::core::{Float, KEY_LENGTH};

unsafe extern "C" fn fpe(
    output: *mut c_double,
    input: c_double,
    key_ptr: *const c_char,
    key_len: c_int,
    tweak_ptr: *const c_char,
    tweak_len: c_int,
    encrypt_flag: bool,
) -> c_int {
    let key_bytes = ffi_read_bytes!("key", key_ptr, key_len);
    let tweak_bytes = ffi_read_bytes!("tweak", tweak_ptr, tweak_len);

    // Copy the contents of the slice into the 32-array
    let key: [u8; KEY_LENGTH] = ffi_unwrap!(key_bytes.try_into(), "key size is 32 bytes");

    let itg = ffi_unwrap!(Float::instantiate(), "cannot instantiate FPE float");

    let operation = match encrypt_flag {
        true => itg.encrypt(&key, tweak_bytes, input),
        false => itg.decrypt(&key, tweak_bytes, input),
    };

    *output = ffi_unwrap!(operation, "fpe encryption/decryption process");

    0
}

/// Encrypts the input `c_double` using the FPE algorithm with the given key and
/// tweak, and stores the result in the `output` pointer. The length of the key
/// and tweak must be specified in `key_len` and `tweak_len` respectively. The
/// function returns an `c_int` indicating success (0) or failure (-1).
///
/// # Safety
///
/// This function is marked as `unsafe` because it accepts pointers to raw
/// memory.
#[no_mangle]
pub unsafe extern "C" fn h_fpe_encrypt_float(
    output: *mut c_double,
    input: c_double,
    key_ptr: *const c_char,
    key_len: c_int,
    tweak_ptr: *const c_char,
    tweak_len: c_int,
) -> c_int {
    fpe(output, input, key_ptr, key_len, tweak_ptr, tweak_len, true)
}

/// Decrypts the input `c_double` using the FPE algorithm with the given key and
/// tweak, and stores the result in the `output` pointer. The length of the key
/// and tweak must be specified in `key_len` and `tweak_len` respectively. The
/// function returns an `c_int` indicating success (0) or failure (-1).
///
/// # Safety
///
/// This function is marked as `unsafe` because it accepts pointers to raw
/// memory.
#[no_mangle]
pub unsafe extern "C" fn h_fpe_decrypt_float(
    output: *mut c_double,
    input: c_double,
    key_ptr: *const c_char,
    key_len: c_int,
    tweak_ptr: *const c_char,
    tweak_len: c_int,
) -> c_int {
    fpe(output, input, key_ptr, key_len, tweak_ptr, tweak_len, false)
}
