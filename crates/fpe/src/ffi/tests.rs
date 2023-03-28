use std::ffi::{c_char, c_int, c_uchar, c_uint, CString};

use cosmian_ffi_utils::error::get_last_error;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::integer::{h_fpe_decrypt_integer, h_fpe_encrypt_integer};
use crate::{
    core::{AnoError, KEY_LENGTH},
    ffi::{
        alphabet::fpe,
        float::{h_fpe_decrypt_float, h_fpe_encrypt_float},
        integer::{h_fpe_decrypt_big_integer, h_fpe_encrypt_big_integer},
    },
    get_alphabet,
};

pub fn random_key() -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut key = [0_u8; KEY_LENGTH];
    rng.fill_bytes(&mut key);
    key
}

/// Performs a Format-Preserving Encryption (FPE) operation on the given input
/// string using the specified parameters.
///
/// # Safety
///
/// This function is marked as `unsafe` because it uses FFI to call external C
/// code (`fpe_alphabet_internal`) and therefore cannot guarantee memory safety
/// or thread safety. It is the caller's responsibility to ensure that the input
/// and output parameters are valid and properly aligned.
///
/// # Arguments
///
/// * `input_str`: A reference to the input string that will be encrypted or
///   decrypted. The string must be a valid UTF-8 sequence.
/// * `alphabet`: A reference to an `Alphabet` object that defines the set of
///   characters that can appear in the input and output strings.
/// * `key_ptr`: A raw pointer to a null-terminated C string that contains the
///   encryption key.
/// * `key_len`: The length of the encryption key in bytes.
/// * `tweak_ptr`: A raw pointer to a null-terminated C string that contains the
///   encryption tweak.
/// * `tweak_len`: The length of the encryption tweak in bytes.
/// * `additional_characters_ptr`: A raw pointer to a null-terminated C string
///   that contains any additional characters that may appear in the input and
///   output strings, but are not part of the `alphabet`.
/// * `encrypt_flag`: A boolean flag that indicates whether the operation should
///   encrypt or decrypt the input string.
///
/// # Returns
///
/// The result of the FPE operation as a `String` object. The output string will
/// have the same length and character set as the input string.
///
/// # Panics
///
/// This function will panic if the `fpe_alphabet_internal` function returns a
/// non-zero error code. The error message will be obtained using the
/// `get_last_error()` function and included in the panic message.
#[allow(clippy::too_many_arguments)]
unsafe fn fpe_alphabet(
    input_str: &str,
    alphabet_id: &str,
    key_ptr: *const c_char,
    key_len: c_int,
    tweak_ptr: *const c_char,
    tweak_len: c_int,
    additional_characters_ptr: *const c_char,
    encrypt_flag: bool,
) -> String {
    // FFI output
    let mut output_bytes = vec![0u8; input_str.len()];
    let output_ptr = output_bytes.as_mut_ptr().cast();
    let mut output_len = output_bytes.len() as c_int;

    // FFI input
    let input_cs = CString::new(input_str).unwrap();
    let input_ptr = input_cs.as_ptr();
    let alphabet_cs = CString::new(alphabet_id).unwrap();
    let alphabet_id_ptr = alphabet_cs.as_ptr();

    let ret = fpe(
        output_ptr,
        &mut output_len,
        input_ptr,
        alphabet_id_ptr,
        key_ptr,
        key_len,
        tweak_ptr,
        tweak_len,
        additional_characters_ptr,
        encrypt_flag,
    );

    if 0 != ret {
        let mut output_bytes = vec![0u8; output_len as usize];
        let output_ptr = output_bytes.as_mut_ptr().cast();
        // Retry with correct output size
        let ret = fpe(
            output_ptr,
            &mut output_len,
            input_ptr,
            alphabet_id_ptr,
            key_ptr,
            key_len,
            tweak_ptr,
            tweak_len,
            additional_characters_ptr,
            encrypt_flag,
        );

        if 0 != ret {
            panic!(
                "FFI fpe process function exit with error: {ret}, error message: {:?}",
                get_last_error()
            );
        } else {
            let output_bytes = std::slice::from_raw_parts(output_ptr, output_len as usize);
            String::from_utf8(output_bytes.to_vec()).unwrap()
        }
    } else {
        let output_bytes: &[u8] =
            std::slice::from_raw_parts(output_ptr as *const u8, output_len as usize);
        String::from_utf8(output_bytes.to_vec()).unwrap()
    }
}

unsafe fn alphabet_check(
    plaintext: &str,
    alphabet_id: &str,
    non_alphabet_chars: &str,
    additional_characters_str: &str,
) {
    // FFI inputs
    let key = random_key();
    let key_ptr = key.as_ptr().cast();
    let key_len = key.len() as c_int;
    let tweak = random_key();
    let tweak_ptr = tweak.as_ptr().cast();
    let tweak_len = tweak.len() as c_int;
    let additional_characters_cs =
        CString::new(additional_characters_str).expect("CString::new failed");
    let additional_characters_ptr = additional_characters_cs.as_ptr();

    let ciphertext = fpe_alphabet(
        plaintext,
        alphabet_id,
        key_ptr,
        key_len,
        tweak_ptr,
        tweak_len,
        additional_characters_ptr,
        true,
    );

    assert_eq!(plaintext.chars().count(), ciphertext.chars().count());
    // every character of the generated string should be part of the alphabet or a
    // '-' or a ' '
    let non_alphabet_u16 = non_alphabet_chars.chars().collect::<Vec<char>>();
    let mut alphabet = get_alphabet(alphabet_id).unwrap();
    alphabet.extend_with(additional_characters_str);
    for c in ciphertext.chars() {
        assert!(non_alphabet_u16.contains(&c) || alphabet.char_to_position(c).is_some());
    }

    let cleartext = fpe_alphabet(
        &ciphertext,
        alphabet_id,
        key_ptr,
        key_len,
        tweak_ptr,
        tweak_len,
        additional_characters_ptr,
        false,
    );

    assert_eq!(cleartext, plaintext);
}

#[test]
fn ffi_fpe_alphabet() -> Result<(), AnoError> {
    unsafe {
        // alphanumeric test
        ["John Doe", "Alba Martinez-Gonzalez", "MalcolmX", "abcd"]
            .iter()
            .for_each(|n| alphabet_check(n, "alpha", " -", ""));

        // extended with space and dash
        ["John Doe", "Alba Martinez-Gonzalez", "MalcolmX", "abcd"]
            .iter()
            .for_each(|n| alphabet_check(n, "alpha", "", " -"));

        // lower case
        ["John Doe", "Alba Martinez-Gonzalez", "MalcolmX", "abcde"]
            .iter()
            .for_each(|n| alphabet_check(&n.to_lowercase(), "alpha_lower", " -", ""));

        // extended with French characters
        ["Bérangère Aigüe", "Ça va bien"]
            // ["Goûter", "René La Taupe", "Bérangère Aigüe", "Ça va bien"]
            .iter()
            .for_each(|n| alphabet_check(n, "latin1sup", " -", ""));

        // extended with French characters
        ["Goûter", "René La Taupe", "Bérangère Aigüe", "Ça va bien"]
            .iter()
            .for_each(|n| alphabet_check(n, "latin1sup", " -", ""));

        [
            "Bérangère Aigüe",
            "ПРС-ТУФХЦЧШЩЪЫЬ ЭЮЯаб-вгдежз ийклмнопрст уфхцчш",
            "吢櫬䀾羑襃￥",
        ]
        .iter()
        .for_each(|n| alphabet_check(n, "utf", " -", ""));

        [
            "天地玄黄 宇宙洪荒",
            "日月盈昃 辰宿列张",
            "寒来暑往 秋收冬藏",
        ]
        .iter()
        .for_each(|n| alphabet_check(n, "chinese", " -", ""));
    }
    Ok(())
}

#[test]
fn ffi_fpe_integer() {
    // FFI inputs
    let key = random_key();
    let key_ptr = key.as_ptr().cast();
    let key_len = key.len() as c_int;
    let tweak = random_key();
    let tweak_ptr = tweak.as_ptr().cast();
    let tweak_len = tweak.len() as c_int;

    let plaintext = 123_456_u64;
    let mut ciphertext = 0_u64;
    unsafe {
        let ret = h_fpe_encrypt_integer(
            &mut ciphertext,
            plaintext,
            10,
            6,
            key_ptr,
            key_len,
            tweak_ptr,
            tweak_len,
        );
        assert!(
            0 == ret,
            "FFI fpe integer encryption exit with error: {ret}, error message: {:?}",
            get_last_error()
        );

        println!(" {plaintext} -> {ciphertext}");

        let mut cleartext = 0_u64;
        let ret = h_fpe_decrypt_integer(
            &mut cleartext,
            ciphertext,
            10,
            6,
            key_ptr,
            key_len,
            tweak_ptr,
            tweak_len,
        );
        assert!(
            0 == ret,
            "FFI fpe integer decryption exit with error: {ret}, error message: {:?}",
            get_last_error()
        );

        println!(" {ciphertext} -> {cleartext}");

        assert_eq!(plaintext, cleartext);
    }
}

type FpeBigIntegerFunction = unsafe extern "C" fn(
    output_ptr: *mut c_uchar,
    output_len: *mut c_int,
    input_ptr: *const c_char,
    radix: c_uint,
    digits: c_uint,
    key_ptr: *const c_char,
    key_len: c_int,
    tweak_ptr: *const c_char,
    tweak_len: c_int,
) -> c_int;

fn fpe_float(plaintext: f64) {
    // FFI inputs
    let key = random_key();
    let key_ptr = key.as_ptr().cast();
    let key_len = key.len() as c_int;
    let tweak = random_key();
    let tweak_ptr = tweak.as_ptr().cast();
    let tweak_len = tweak.len() as c_int;

    let mut ciphertext = 0_f64;
    unsafe {
        let ret = h_fpe_encrypt_float(
            &mut ciphertext,
            plaintext,
            key_ptr,
            key_len,
            tweak_ptr,
            tweak_len,
        );
        assert!(
            0 == ret,
            "FFI fpe integer encryption exit with error: {ret}, error message: {:?}",
            get_last_error()
        );

        println!(" {plaintext} -> {ciphertext}");

        let mut cleartext = 0_f64;
        let ret = h_fpe_decrypt_float(
            &mut cleartext,
            ciphertext,
            key_ptr,
            key_len,
            tweak_ptr,
            tweak_len,
        );
        assert!(
            0 == ret,
            "FFI fpe integer decryption exit with error: {ret}, error message: {:?}",
            get_last_error()
        );

        println!(" {ciphertext} -> {cleartext}");

        assert_eq!(plaintext, cleartext);
    }
}

#[test]
fn ffi_fpe_float() {
    [1_f64, 123_456.789_f64, 123_456_789.123_456_f64]
        .into_iter()
        .for_each(fpe_float);
}

#[allow(clippy::too_many_arguments)]
unsafe fn fpe_big_integer(
    input_str: &str,
    radix: u32,
    digits: u32,
    key_ptr: *const c_char,
    key_len: c_int,
    tweak_ptr: *const c_char,
    tweak_len: c_int,
    fct: FpeBigIntegerFunction,
) -> String {
    // FFI output
    let mut output_bytes = vec![0u8; input_str.len()];
    let output_ptr = output_bytes.as_mut_ptr().cast();
    let mut output_len = output_bytes.len() as c_int;

    // FFI input
    let input_cs = CString::new(input_str).unwrap();
    let input_ptr = input_cs.as_ptr();

    let ret = fct(
        output_ptr,
        &mut output_len,
        input_ptr,
        radix,
        digits,
        key_ptr,
        key_len,
        tweak_ptr,
        tweak_len,
    );

    if 0 != ret {
        let mut output_bytes = vec![0u8; output_len as usize];
        let output_ptr = output_bytes.as_mut_ptr().cast();
        // Retry with correct output size
        let ret = fct(
            output_ptr,
            &mut output_len,
            input_ptr,
            radix,
            digits,
            key_ptr,
            key_len,
            tweak_ptr,
            tweak_len,
        );

        if 0 != ret {
            panic!(
                "FFI fpe big integer exit with error: {ret}, error message: {:?}",
                get_last_error()
            );
        } else {
            let output_bytes = std::slice::from_raw_parts(output_ptr, output_len as usize);
            String::from_utf8(output_bytes.to_vec()).unwrap()
        }
    } else {
        let output_bytes: &[u8] =
            std::slice::from_raw_parts(output_ptr as *const u8, output_len as usize);
        String::from_utf8(output_bytes.to_vec()).unwrap()
    }
}

fn big_integer(plaintext: &str, radix: u32, digits: u32) {
    // FFI inputs
    let key = random_key();
    let key_ptr = key.as_ptr().cast();
    let key_len = key.len() as c_int;
    let tweak = random_key();
    let tweak_ptr = tweak.as_ptr().cast();
    let tweak_len = tweak.len() as c_int;

    unsafe {
        let ciphertext = fpe_big_integer(
            plaintext,
            radix,
            digits,
            key_ptr,
            key_len,
            tweak_ptr,
            tweak_len,
            h_fpe_encrypt_big_integer,
        );

        println!(" {plaintext} -> {ciphertext}");

        let cleartext = fpe_big_integer(
            &ciphertext,
            radix,
            digits,
            key_ptr,
            key_len,
            tweak_ptr,
            tweak_len,
            h_fpe_decrypt_big_integer,
        );

        println!(" {ciphertext} -> {cleartext}");
        assert_eq!(plaintext, cleartext);
    }
}

#[test]
fn ffi_fpe_big_integer() {
    ["10", "100", "1000", "10000", "100000"]
        .iter()
        .for_each(|n| big_integer(n, 10, 6));
}
