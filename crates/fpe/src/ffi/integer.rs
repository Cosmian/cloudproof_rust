use cosmian_ffi_utils::{ffi_read_bytes, ffi_read_string, ffi_unwrap, ffi_write_bytes};
use num_bigint::BigUint;
use num_traits::Num;

use crate::core::{Integer, KEY_LENGTH};

unsafe extern "C" fn fpe(
    output: *mut u64,
    input: u64,
    radix: u32,
    digits: u32,
    key_ptr: *const i8,
    key_len: i32,
    tweak_ptr: *const i8,
    tweak_len: i32,
    encrypt_flag: bool,
) -> i32 {
    let key_bytes = ffi_read_bytes!("key", key_ptr, key_len);
    let tweak_bytes = ffi_read_bytes!("tweak", tweak_ptr, tweak_len);

    // Copy the contents of the slice into the 32-array
    let key: [u8; KEY_LENGTH] = ffi_unwrap!(key_bytes.try_into(), "key size is 32 bytes");

    let itg = ffi_unwrap!(
        Integer::instantiate(radix, digits as usize),
        "cannot instantiate FPE integer"
    );

    *output = if encrypt_flag {
        ffi_unwrap!(
            itg.encrypt(&key, tweak_bytes, input),
            "fpe encryption process"
        )
    } else {
        ffi_unwrap!(
            itg.decrypt(&key, tweak_bytes, input),
            "fpe decryption process"
        )
    };

    0
}

/// Encrypts an integer using the format-preserving encryption (FPE) algorithm.
///
/// # Safety
///
/// This function is marked as `unsafe` because it takes raw pointers as input,
/// which must be valid and dereferenceable for the function to work correctly.
///
/// # Arguments
///
/// * `output`: A mutable pointer to the location where the encrypted output
///   value will be stored.
/// * `input`: The integer value to be encrypted.
/// * `radix`: The radix of the numeric system being used.
/// * `digits`: The number of digits in the numeric system being used.
/// * `key_ptr`: A pointer to the key to be used for encryption.
/// * `key_len`: The length of the key in bytes.
/// * `tweak_ptr`: A pointer to the tweak value to be used for encryption.
/// * `tweak_len`: The length of the tweak in bytes.
///
/// # Returns
///
/// An integer value indicating whether the encryption was successful or not. A
/// return value of 0 indicates success, while any other value indicates an
/// error.
#[no_mangle]
pub unsafe extern "C" fn h_fpe_encrypt_integer(
    output: *mut u64,
    input: u64,
    radix: u32,
    digits: u32,
    key_ptr: *const i8,
    key_len: i32,
    tweak_ptr: *const i8,
    tweak_len: i32,
) -> i32 {
    fpe(
        output, input, radix, digits, key_ptr, key_len, tweak_ptr, tweak_len, true,
    )
}

/// Decrypts an integer using the format-preserving encryption (FPE) algorithm.
///
/// # Safety
///
/// This function is marked as `unsafe` because it takes raw pointers as input,
/// which must be valid and dereferenceable for the function to work correctly.
///
/// # Arguments
///
/// * `output`: A mutable pointer to the location where the encrypted output
///   value will be stored.
/// * `input`: The integer value to be encrypted.
/// * `radix`: The radix of the numeric system being used.
/// * `digits`: The number of digits in the numeric system being used.
/// * `key_ptr`: A pointer to the key to be used for encryption.
/// * `key_len`: The length of the key in bytes.
/// * `tweak_ptr`: A pointer to the tweak value to be used for encryption.
/// * `tweak_len`: The length of the tweak in bytes.
///
/// # Returns
///
/// An integer value indicating whether the encryption was successful or not. A
/// return value of 0 indicates success, while any other value indicates an
/// error.
#[no_mangle]
pub unsafe extern "C" fn h_fpe_decrypt_integer(
    output: *mut u64,
    input: u64,
    radix: u32,
    digits: u32,
    key_ptr: *const i8,
    key_len: i32,
    tweak_ptr: *const i8,
    tweak_len: i32,
) -> i32 {
    fpe(
        output, input, radix, digits, key_ptr, key_len, tweak_ptr, tweak_len, false,
    )
}

unsafe extern "C" fn fpe_big_integer(
    output_ptr: *mut u8,
    output_len: *mut i32,
    input_ptr: *const i8,
    radix: u32,
    digits: u32,
    key_ptr: *const i8,
    key_len: i32,
    tweak_ptr: *const i8,
    tweak_len: i32,
    encrypt_flag: bool,
) -> i32 {
    let key_bytes = ffi_read_bytes!("key", key_ptr, key_len);
    let tweak_bytes = ffi_read_bytes!("tweak", tweak_ptr, tweak_len);
    let input_str = ffi_read_string!("input", input_ptr);

    let itg = ffi_unwrap!(
        Integer::instantiate(radix, digits as usize),
        "cannot instantiate FPE integer"
    );
    let input_biguint = ffi_unwrap!(
        BigUint::from_str_radix(&input_str, radix),
        "failed to convert
input to BigUint"
    );

    // Copy the contents of the slice into the 32-array
    let key: [u8; KEY_LENGTH] = ffi_unwrap!(key_bytes.try_into(), "key size is 32 bytes");

    let output = if encrypt_flag {
        ffi_unwrap!(
            itg.encrypt_big(&key, tweak_bytes, &input_biguint),
            "fpe encryption process"
        )
    } else {
        ffi_unwrap!(
            itg.decrypt_big(&key, tweak_bytes, &input_biguint),
            "fpe decryption process"
        )
    };

    let output_str = output.to_str_radix(radix);

    ffi_write_bytes!("output_ptr", output_str.as_bytes(), output_ptr, output_len);
}

/// Encrypts an input big integer using the FPE algorithm and returns the
/// encrypted value as an array of bytes.
///
/// # Arguments
///
/// * `output_ptr` - a pointer to the output buffer where the encrypted bytes
///   will be written
/// * `output_len` - a pointer to an integer that will be updated with the
///   length of the encrypted bytes
/// * `input_ptr` - a pointer to the input buffer that contains the big integer
///   to be encrypted
/// * `radix` - the radix of the input big integer
/// * `digits` - the number of digits in the input big integer
/// * `key_ptr` - a pointer to the key buffer that will be used for encryption
/// * `key_len` - the length of the key buffer
/// * `tweak_ptr` - a pointer to the tweak buffer that will be used for
///   encryption
/// * `tweak_len` - the length of the tweak buffer
///
/// # Safety
///
/// This function is marked unsafe because it operates on raw pointers and
/// performs unsafe memory operations.
///
/// # Returns
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn h_fpe_encrypt_big_integer(
    output_ptr: *mut u8,
    output_len: *mut i32,
    input_ptr: *const i8,
    radix: u32,
    digits: u32,
    key_ptr: *const i8,
    key_len: i32,
    tweak_ptr: *const i8,
    tweak_len: i32,
) -> i32 {
    fpe_big_integer(
        output_ptr, output_len, input_ptr, radix, digits, key_ptr, key_len, tweak_ptr, tweak_len,
        true,
    )
}

/// Decrypts an input big integer using the FPE algorithm and returns the
/// decrypted value as an array of bytes.
///
/// # Arguments
///
/// * `output_ptr` - a pointer to the output buffer where the decrypted bytes
///   will be written
/// * `output_len` - a pointer to an integer that will be updated with the
///   length of the decrypted bytes
/// * `input_ptr` - a pointer to the input buffer that contains the big integer
///   to be decrypted
/// * `radix` - the radix of the input big integer
/// * `digits` - the number of digits in the input big integer
/// * `key_ptr` - a pointer to the key buffer that will be used for decryption
/// * `key_len` - the length of the key buffer
/// * `tweak_ptr` - a pointer to the tweak buffer that will be used for
///   decryption
/// * `tweak_len` - the length of the tweak buffer
///
/// # Safety
///
/// This function is marked unsafe because it operates on raw pointers and
/// performs unsafe memory operations.
///
/// # Returns
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn h_fpe_decrypt_big_integer(
    output_ptr: *mut u8,
    output_len: *mut i32,
    input_ptr: *const i8,
    radix: u32,
    digits: u32,
    key_ptr: *const i8,
    key_len: i32,
    tweak_ptr: *const i8,
    tweak_len: i32,
) -> i32 {
    fpe_big_integer(
        output_ptr, output_len, input_ptr, radix, digits, key_ptr, key_len, tweak_ptr, tweak_len,
        false,
    )
}
