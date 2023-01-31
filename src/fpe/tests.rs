use crate::{
    error::AnoError,
    fpe::{
        alphabets::Alphabet,
        ff1::{FPE, KEY_LENGTH},
    },
};
use rand::{thread_rng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_distr::Alphanumeric;

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
    assert_eq!(ciphertext.len(), plaintext.len());
    // every character of the generated string should be part of the alphabet or a - or a ' '
    for c in ciphertext.chars() {
        assert!(non_alphabet_chars.contains(c) || alphabet.chars.contains(&c));
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
fn fpe_ff1_string_same_alphabet() -> Result<(), AnoError> {
    let key = random_key();
    for _ in 0..100 {
        let plaintext_len = thread_rng().gen_range(8..128);
        let plaintext: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(plaintext_len)
            .map(char::from)
            .collect();
        let ciphertext = FPE::encrypt_string(&key, &[], &plaintext, &plaintext)?;
        // cipher text size should equal that of the plain text
        assert_eq!(ciphertext.len(), plaintext.len());
        // every character of the generated string should be part of the alphabet of the original string
        for c in ciphertext.chars() {
            assert!(plaintext.contains(c));
        }
        let cleartext = FPE::decrypt_string(&key, &[], &plaintext, ciphertext.as_str())?;
        assert_eq!(cleartext, plaintext);
    }
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
    let alphabet = Alphabet::alpha();
    ["John Doe", "Alba Martinez-Gonzalez", "MalcomX", "abcd"]
        .iter()
        .for_each(|n| alphabet_check(n, &alphabet, " -"));
    let alphabet = alphabet.extend_with(" -");
    ["John Doe", "Alba Martinez-Gonzalez", "MalcomX", "abcd"]
        .iter()
        .for_each(|n| alphabet_check(n, &alphabet, ""));
    let alphabet = Alphabet::alpha_lower();
    ["John Doe", "Alba Martinez-Gonzalez", "MalcomX", "abcde"]
        .iter()
        .for_each(|n| alphabet_check(&n.to_lowercase(), &alphabet, " -"));
    Ok(())
}

#[test]
fn fpe_ff1_u16_credit_card_number() -> Result<(), AnoError> {
    let ccn = "1234123412341234";
    let key = random_key();
    let plaintext = ccn
        .as_bytes()
        .iter()
        .map(|b| u16::from(*b))
        .collect::<Vec<_>>();
    let ciphertext = FPE::encrypt_u16(&key, &[], 128, plaintext.clone())?;
    println!("{:?} -> {:?} ", &plaintext, &ciphertext);
    let cleartext = FPE::decrypt_u16(&key, &[], 128, ciphertext)?;
    assert_eq!(cleartext, plaintext);
    Ok(())
}

#[test]
fn fpe_ff1_u8_credit_card_number() -> Result<(), AnoError> {
    let ccn = "1234-1234-1234-1234";
    let plaintext = ccn.as_bytes().to_vec();
    let key = random_key();
    let ciphertext = FPE::encrypt_u8(&key, &[], 128, plaintext.clone())?;
    let cleartext = FPE::decrypt_u8(&key, &[], 128, ciphertext)?;
    assert_eq!(cleartext, plaintext);
    Ok(())
}

#[test]
fn fpe_ff1_u16_range_test() -> Result<(), AnoError> {
    let key = random_key();

    for _ in 1..100 {
        let plaintext = vec![0_u16; 32]
            .into_iter()
            .map(|_| thread_rng().gen_range(0..128))
            .collect::<Vec<_>>();
        let ciphertext = FPE::encrypt_u16(&key, &[], 128, plaintext.clone())?;
        let cleartext = FPE::decrypt_u16(&key, &[], 128, ciphertext)?;
        assert_eq!(cleartext, plaintext);
    }
    Ok(())
}

#[test]
fn fpe_ff1_digits_encryption() -> Result<(), AnoError> {
    let key = random_key();

    // Length == 0
    let pt = "0";
    let ct = FPE::encrypt_digit_string::<u32>(&key, &[], pt)?;
    let cleartext = FPE::decrypt_digits_string::<u32>(&key, &[], ct.as_str())?;
    assert_eq!(cleartext, pt);

    // Length < 9
    let pt: String = thread_rng().gen::<u16>().to_string();
    let ct = FPE::encrypt_digit_string::<u32>(&key, &[], &pt)?;
    let cleartext = FPE::decrypt_digits_string::<u32>(&key, &[], ct.as_str())?;
    assert_eq!(cleartext, pt);

    // Length < 9. Signed integer.
    let pt: String = thread_rng().gen::<i16>().to_string();
    let ct = FPE::encrypt_digit_string::<i32>(&key, &[], &pt)?;
    let cleartext = FPE::decrypt_digits_string::<i32>(&key, &[], ct.as_str())?;
    assert_eq!(cleartext, pt);

    // Length >= 9
    let pt = "4294967295"; // 2^32 - 1
    let ct = FPE::encrypt_digit_string::<u32>(&key, &[], pt)?;
    let cleartext = FPE::decrypt_digits_string::<u32>(&key, &[], ct.as_str())?;
    assert_eq!(cleartext, pt);

    // Length >= 9, splitted input with right string prepended with 0
    let pt = "1111111111000222222";
    let ct = FPE::encrypt_digit_string::<u64>(&key, &[], pt)?;
    let cleartext = FPE::decrypt_digits_string::<u64>(&key, &[], ct.as_str())?;
    assert_eq!(cleartext, pt);

    // Length >= 9 with non-digit character. Needs to respect input format
    let pt = "1234-1234-1234-1234-1234";
    let ct = FPE::encrypt_string(&key, &[], "1234567890", pt)?;
    let cleartext = FPE::decrypt_string(&key, &[], "1234567890", ct.as_str())?;
    assert_eq!(cleartext, pt);

    // Non-digits characters
    let pt = "aaaaaaaaaaaaaa";
    let ct = FPE::encrypt_digit_string::<u32>(&key, &[], pt);
    assert!(ct.is_err());
    Ok(())
}

#[test]
fn fpe_ff1_limit_cases() -> Result<(), AnoError> {
    let key = random_key();

    let pt = "4294967295"; // 2^32 - 1
    let ct = FPE::encrypt_digit_string::<u32>(&key, &[], pt)?;
    let cleartext = FPE::decrypt_digits_string::<u32>(&key, &[], ct.as_str())?;
    assert_eq!(cleartext, pt);

    let pt = "-4294967295"; // too big
    let ct = FPE::encrypt_digit_string::<u32>(&key, &[], pt)?;
    let cleartext = FPE::decrypt_digits_string::<u32>(&key, &[], ct.as_str())?;
    assert_eq!(cleartext, pt);

    Ok(())
}

#[test]
fn fpe_ff1_digits_range_test() -> Result<(), AnoError> {
    let key = random_key();

    for _ in 0..1000 {
        let plaintext: String = thread_rng().gen::<i32>().to_string();
        let ciphertext = FPE::encrypt_digit_string::<i32>(&key, &[], &plaintext)?;
        let cleartext = FPE::decrypt_digits_string::<i32>(&key, &[], ciphertext.as_str())?;
        assert_eq!(cleartext, plaintext);
    }
    Ok(())
}
