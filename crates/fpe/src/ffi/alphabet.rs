use cosmian_ffi_utils::{ffi_read_bytes, ffi_read_string, ffi_unwrap, ffi_write_bytes, ErrorCode};

use crate::get_alphabet;

#[allow(clippy::too_many_arguments)]
pub unsafe fn fpe(
    output_ptr: *mut u8,
    output_len: *mut i32,
    input_ptr: *const i8,
    alphabet_id_ptr: *const i8,
    key_ptr: *const i8,
    key_len: i32,
    tweak_ptr: *const i8,
    tweak_len: i32,
    additional_characters_ptr: *const i8,
    encrypt_flag: bool,
) -> i32 {
    let key_bytes = ffi_read_bytes!("key", key_ptr, key_len);
    let tweak_bytes = ffi_read_bytes!("tweak", tweak_ptr, tweak_len);
    let input_str = ffi_read_string!("input", input_ptr);
    let alphabet_id_str = ffi_read_string!("alphabet_id", alphabet_id_ptr);

    let mut alphabet = ffi_unwrap!(
        get_alphabet(&alphabet_id_str),
        "Alphabet id not supported",
        ErrorCode::Fpe.into()
    );
    let additional_characters_str =
        ffi_read_string!("additional_characters_ptr", additional_characters_ptr);
    alphabet.extend_with(&additional_characters_str);

    let output_str = if encrypt_flag {
        ffi_unwrap!(
            alphabet.encrypt(key_bytes, tweak_bytes, &input_str),
            "fpe encryption process",
            ErrorCode::Encryption.into()
        )
    } else {
        ffi_unwrap!(
            alphabet.decrypt(key_bytes, tweak_bytes, &input_str),
            "fpe decryption process",
            ErrorCode::Decryption.into()
        )
    };

    ffi_write_bytes!("output_ptr", output_str.as_bytes(), output_ptr, output_len);
}

/// Encrypts a string using Format Preserving Encryption (FPE) algorithm with
/// the specified alphabet.
///
/// # Safety
///
/// This function is marked as `unsafe` due to the usage of raw pointers, which
/// need to be properly allocated and dereferenced by the caller.
///
/// # Arguments
///
/// * `plaintext_ptr` - a pointer to the buffer where the encrypted string will
///   be written.
/// * `plaintext_len` - a pointer to the variable that stores the maximum size
///   of the `plaintext_ptr` buffer. After the function call, the variable will
///   be updated with the actual size of the encrypted string.
/// * `alphabet_id_ptr` - a pointer to a C string that represents the ID of the
///   alphabet used for encryption.
/// * `input_ptr` - a pointer to a C string that represents the plaintext to be
///   encrypted.
/// * `key_ptr` - a pointer to a C string that represents the key used for
///   encryption.
/// * `key_len` - the length of the `key_ptr` string.
/// * `tweak_ptr` - a pointer to a C string that represents the tweak used for
///   encryption.
/// * `tweak_len` - the length of the `tweak_ptr` string.
/// * `additional_characters_ptr` - a pointer to a C string that represents
///   additional characters to be used in the alphabet.
///
/// # Returns
///
/// An integer that indicates whether the encryption was successful. A value of
/// `0` means success, while a non-zero value represents an error code.
#[no_mangle]
pub unsafe extern "C" fn h_fpe_encrypt_alphabet(
    plaintext_ptr: *mut u8,
    plaintext_len: *mut i32,
    alphabet_id_ptr: *const i8,
    input_ptr: *const i8,
    key_ptr: *const i8,
    key_len: i32,
    tweak_ptr: *const i8,
    tweak_len: i32,
    additional_characters_ptr: *const i8,
) -> i32 {
    // Calls the internal FPE encryption function with the specified alphabet and
    // sets the "encrypt" flag to true.
    fpe(
        plaintext_ptr,
        plaintext_len,
        input_ptr,
        alphabet_id_ptr,
        key_ptr,
        key_len,
        tweak_ptr,
        tweak_len,
        additional_characters_ptr,
        true,
    )
}

/// Decrypts a string using Format Preserving Encryption (FPE) algorithm with
/// the specified alphabet.
///
/// # Safety
///
/// This function is marked as `unsafe` due to the usage of raw pointers, which
/// need to be properly allocated and dereferenced by the caller.
///
/// # Arguments
///
/// * `ciphertext_ptr` - a pointer to the buffer where the encrypted string will
///   be written.
/// * `ciphertext_len` - a pointer to the variable that stores the maximum size
///   of the `ciphertext_ptr` buffer. After the function call, the variable will
///   be updated with the actual size of the encrypted string.
/// * `alphabet_id_ptr` - a pointer to a C string that represents the ID of the
///   alphabet used for encryption.
/// * `input_ptr` - a pointer to a C string that represents the plaintext to be
///   encrypted.
/// * `key_ptr` - a pointer to a C string that represents the key used for
///   encryption.
/// * `key_len` - the length of the `key_ptr` string.
/// * `tweak_ptr` - a pointer to a C string that represents the tweak used for
///   encryption.
/// * `tweak_len` - the length of the `tweak_ptr` string.
/// * `additional_characters_ptr` - a pointer to a C string that represents
///   additional characters to be used in the alphabet.
///
/// # Returns
///
/// An integer that indicates whether the encryption was successful. A value of
/// `0` means success, while a non-zero value represents an error code.
#[no_mangle]
pub unsafe extern "C" fn h_fpe_decrypt_alphabet(
    ciphertext_ptr: *mut u8,
    ciphertext_len: *mut i32,
    alphabet_id_ptr: *const i8,
    input_ptr: *const i8,
    key_ptr: *const i8,
    key_len: i32,
    tweak_ptr: *const i8,
    tweak_len: i32,
    additional_characters_ptr: *const i8,
) -> i32 {
    fpe(
        ciphertext_ptr,
        ciphertext_len,
        input_ptr,
        alphabet_id_ptr,
        key_ptr,
        key_len,
        tweak_ptr,
        tweak_len,
        additional_characters_ptr,
        false,
    )
}
