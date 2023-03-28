use num_bigint::BigUint;
use num_traits::Num;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::core::{Integer, KEY_LENGTH};

fn fpe(
    input: &str,
    radix: u32,
    digits: usize,
    key: Vec<u8>,
    tweak: Vec<u8>,
    encrypt_flag: bool,
) -> Result<String, JsValue> {
    // Copy the key bytes into a 32-byte array
    let k: [u8; KEY_LENGTH] = key.try_into().map_err(|_e| {
        JsValue::from_str(&format!(
            "FPE Float error: key length incorrect: expected {KEY_LENGTH}"
        ))
    })?;

    // Instantiate an FPE integer with the provided radix and digit count
    let itg = Integer::instantiate(radix, digits)
        .map_err(|e| JsValue::from_str(&format!("FPE Big Integer instantiation failed: {e:?}")))?;

    // Convert the input string to a BigUint
    let input_biguint = BigUint::from_str_radix(input, radix).map_err(|e| {
        JsValue::from_str(&format!(
            "FPE Big Integer: conversion to BigUint failed: {e:?}"
        ))
    })?;

    // Perform the encryption or decryption operation on the input BigUint
    let result = if encrypt_flag {
        itg.encrypt_big(&k, &tweak, &input_biguint)
    } else {
        itg.decrypt_big(&k, &tweak, &input_biguint)
    };

    // Convert the result to a string in the provided radix
    let output = result.map_err(|e| {
        JsValue::from_str(&format!(
            "FPE Big Integer encryption/decryption failed: {e:?}"
        ))
    })?;
    let output_str = output.to_str_radix(radix);
    Ok(output_str)
}

#[wasm_bindgen]
pub fn webassembly_fpe_encrypt_big_integer(
    input: &str,
    radix: u32,
    digits: usize,
    key: Vec<u8>,
    tweak: Vec<u8>,
) -> Result<String, JsValue> {
    fpe(input, radix, digits, key, tweak, true)
}

#[wasm_bindgen]
pub fn webassembly_fpe_decrypt_big_integer(
    input: &str,
    radix: u32,
    digits: usize,
    key: Vec<u8>,
    tweak: Vec<u8>,
) -> Result<String, JsValue> {
    fpe(input, radix, digits, key, tweak, false)
}
