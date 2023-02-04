use super::{Number, KEY_LENGTH};
use crate::{error::AnoError, fpe::Alphabet};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::{thread_rng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_distr::Alphanumeric;

/// Generate a random key using a cryptographically
/// secure random number generator that is suitable for use with FPE
pub fn random_key() -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut key = [0_u8; KEY_LENGTH];
    rng.fill_bytes(&mut key);
    key
}

fn alphabet_check(plaintext: &str, alphabet: &Alphabet, non_alphabet_chars: &str) {
    let key = random_key();
    let ciphertext = alphabet.encrypt(&key, &[], plaintext).unwrap();
    println!("  {:?} -> {:?} ", &plaintext, &ciphertext);
    assert_eq!(plaintext.chars().count(), ciphertext.chars().count());
    // every character of the generated string should be part of the alphabet or a - or a ' '
    let non_alphabet_u16 = non_alphabet_chars.chars().collect::<Vec<char>>();
    for c in ciphertext.chars() {
        assert!(non_alphabet_u16.contains(&c) || alphabet.char_to_position(c).is_some());
    }
    let cleartext = alphabet.decrypt(&key, &[], ciphertext.as_str()).unwrap();
    assert_eq!(cleartext, plaintext);
}

#[test]
fn test_doc_example() -> Result<(), AnoError> {
    let alphabet = Alphabet::alpha_lower(); //same as above
    let key = [0_u8; 32];
    let tweak = b"unique tweak";
    let plaintext = "plaintext";
    let ciphertext = alphabet.encrypt(&key, tweak, plaintext)?;
    assert_eq!(ciphertext, "phqivnqmo");
    let cleartext = alphabet.decrypt(&key, tweak, &ciphertext)?;
    assert_eq!(cleartext, plaintext);
    Ok(())
}

#[test]
fn fpe_ff1_credit_card_number() -> Result<(), AnoError> {
    let alphabet = Alphabet::numeric();
    [
        "1234-1234-1234-1234",
        "0000-0000-0000-0000",
        "1234-5678-9012-3456",
    ]
    .iter()
    .for_each(|n| alphabet_check(n, &alphabet, "-"));
    Ok(())
}

#[test]
fn fpe_ff1_names() -> Result<(), AnoError> {
    // alphanumeric test
    let mut alphabet = Alphabet::alpha();

    ["John Doe", "Alba Martinez-Gonzalez", "MalcomX", "abcd"]
        .iter()
        .for_each(|n| alphabet_check(n, &alphabet, " -"));

    // extended with space and dash
    alphabet.extend_with(" -");
    ["John Doe", "Alba Martinez-Gonzalez", "MalcomX", "abcd"]
        .iter()
        .for_each(|n| alphabet_check(n, &alphabet, ""));

    // lower case
    let alphabet = Alphabet::alpha_lower();
    ["John Doe", "Alba Martinez-Gonzalez", "MalcomX", "abcde"]
        .iter()
        .for_each(|n| alphabet_check(&n.to_lowercase(), &alphabet, " -"));

    // extended with French characters
    let alphabet = Alphabet::latin1sup();
    ["Goûter", "René La Taupe", "Bérangère Aigüe", "Ça va bien"]
        .iter()
        .for_each(|n| alphabet_check(n, &alphabet, " -"));

    // extended with French characters
    let alphabet = Alphabet::latin1sup_alphanum();
    ["Goûter", "René La Taupe", "Bérangère Aigüe", "Ça va bien"]
        .iter()
        .for_each(|n| alphabet_check(n, &alphabet, " -"));

    let alphabet = Alphabet::utf();
    [
        "Bérangère Aigüe",
        "ПРС-ТУФХЦЧШЩЪЫЬ ЭЮЯаб-вгдежз ийклмнопрст уфхцчш",
        "吢櫬䀾羑襃￥",
    ]
    .iter()
    .for_each(|n| alphabet_check(n, &alphabet, " -"));

    let alphabet = Alphabet::chinese();
    [
        "天地玄黄 宇宙洪荒",
        "日月盈昃 辰宿列张",
        "寒来暑往 秋收冬藏",
    ]
    .iter()
    .for_each(|n| alphabet_check(n, &alphabet, " -"));

    Ok(())
}

#[test]
fn fpe_ff1_string_same_alphabet() -> Result<(), AnoError> {
    for _ in 0..100 {
        let plaintext_len = thread_rng().gen_range(8..257);
        let plaintext: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(plaintext_len)
            .map(char::from)
            .collect();
        let alphabet = Alphabet::try_from(&plaintext)?;
        alphabet_check(&plaintext, &alphabet, "");
    }
    Ok(())
}

fn fpe_number_u64_(radix: u32, min_length: usize) -> Result<(), AnoError> {
    let key = random_key();
    let mut rng = thread_rng();
    for _i in 0..20 {
        let digits = rng.gen_range(min_length..min_length + 9);
        let number = Number::from(radix, digits)?;
        for _j in 0..10 {
            let value = rng.gen_range(0..number.max_value.to_u64().unwrap());
            let ciphertext = number.encrypt(value, &key, &[])?;
            assert!(ciphertext <= number.max_value().to_u64().unwrap());
            assert_eq!(number.decrypt(ciphertext, &key, &[])?, value);
        }
    }

    Ok(())
}

#[test]
fn fpe_number_u64() -> Result<(), AnoError> {
    for i in 2..=16 {
        //2 => 20
        let min_length = match i {
            2 => 20,
            3 => 13,
            4 => 10,
            5 => 9,
            6 => 8,
            7 => 8,
            8 => 7,
            9 => 7,
            10 => 6,
            11 => 6,
            12 => 6,
            13 => 6,
            14 => 6,
            15 => 6,
            16 => 5,
            _ => 1,
        };
        fpe_number_u64_(i, min_length)?;
    }
    Ok(())
}

#[test]
fn fpe_number_big_uint() -> Result<(), AnoError> {
    let key = random_key();
    let mut rng = thread_rng();
    for radix in 2..=16 {
        let base = BigUint::from(radix);
        for _i in 0..20 {
            let digits = rng.gen_range(24..32);
            let number = Number::from(radix, digits)?;
            for _j in 0..10 {
                let exponent = rng.gen_range(0..digits - 1);
                let value = base.pow(exponent.to_u32().unwrap());
                let ciphertext = number.encrypt_big(&value, &key, &[])?;
                assert!(ciphertext <= number.max_value());
                assert_eq!(number.decrypt_big(&ciphertext, &key, &[])?, value);
            }
        }
    }

    Ok(())
}
