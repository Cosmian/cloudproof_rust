use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{
    core::KEY_LENGTH,
    get_alphabet,
    wasm_bindgen::{
        alphabet::{webassembly_fpe_decrypt_alphabet, webassembly_fpe_encrypt_alphabet},
        float::{webassembly_fpe_decrypt_float, webassembly_fpe_encrypt_float},
        integer::{webassembly_fpe_decrypt_big_integer, webassembly_fpe_encrypt_big_integer},
    },
};

pub fn random_key() -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut key = [0_u8; KEY_LENGTH];
    rng.fill_bytes(&mut key);
    key
}

fn alphabet_check(
    plaintext: &str,
    alphabet_id: &str,
    non_alphabet_chars: &str,
    additional_characters_str: &str,
) {
    let key = random_key().to_vec();
    let tweak = random_key().to_vec();

    let ciphertext = webassembly_fpe_encrypt_alphabet(
        plaintext,
        alphabet_id,
        key.clone(),
        tweak.clone(),
        additional_characters_str,
    )
    .unwrap();

    assert_eq!(plaintext.chars().count(), ciphertext.chars().count());
    // every character of the generated string should be part of the alphabet or a
    // '-' or a ' '
    let non_alphabet_u16 = non_alphabet_chars.chars().collect::<Vec<char>>();
    let mut alphabet = get_alphabet(alphabet_id).unwrap();
    alphabet.extend_with(additional_characters_str);
    for c in ciphertext.chars() {
        assert!(non_alphabet_u16.contains(&c) || alphabet.char_to_position(c).is_some());
    }

    let cleartext = webassembly_fpe_decrypt_alphabet(
        &ciphertext,
        alphabet_id,
        key,
        tweak,
        additional_characters_str,
    )
    .unwrap();

    assert_eq!(cleartext, plaintext);
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt() {
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

#[wasm_bindgen_test]
fn test_big_integer() {
    let key = random_key().to_vec();
    let tweak = random_key().to_vec();
    let plaintext = "1000000000000000000000000000";
    let radix = 10;
    let digits = 40;
    let ciphertext =
        webassembly_fpe_encrypt_big_integer(plaintext, radix, digits, key.clone(), tweak.clone())
            .unwrap();
    let cleartext =
        webassembly_fpe_decrypt_big_integer(&ciphertext, radix, digits, key, tweak).unwrap();
    assert_eq!(cleartext, plaintext);
}

#[wasm_bindgen_test]
fn test_float() {
    let key = random_key().to_vec();
    let tweak = random_key().to_vec();
    let plaintext = 123_456.789_f64;
    let ciphertext = webassembly_fpe_encrypt_float(plaintext, key.clone(), tweak.clone()).unwrap();
    let cleartext = webassembly_fpe_decrypt_float(ciphertext, key, tweak).unwrap();
    assert_eq!(cleartext, plaintext);
}
