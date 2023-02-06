use super::{Float, Integer, KEY_LENGTH};
use crate::{error::AnoError, fpe::Alphabet};
use num_bigint::BigUint;
use num_traits::{Num, ToPrimitive};
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
fn test_readme_examples() -> Result<(), AnoError> {
    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        let alphabet = Alphabet::alpha_numeric(); //0-9a-zA-Z
        let ciphertext = alphabet.encrypt(&key, tweak, "alphanumeric").unwrap();
        let plaintext = alphabet.decrypt(&key, tweak, &ciphertext).unwrap();
        assert_eq!("jraqSuFWZmdH", ciphertext);
        assert_eq!("alphanumeric", plaintext);
    }
    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        let alphabet = Alphabet::numeric(); //0-9
        let ciphertext = alphabet
            .encrypt(&key, tweak, "1234-1234-1234-1234")
            .unwrap();
        let plaintext = alphabet.decrypt(&key, tweak, &ciphertext).unwrap();
        assert_eq!("1415-4650-5562-7272", ciphertext);
        assert_eq!("1234-1234-1234-1234", plaintext);
    }
    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        let mut alphabet = Alphabet::chinese();
        // add the space character to the alphabet
        alphabet.extend_with(" ");
        let ciphertext = alphabet.encrypt(&key, tweak, "天地玄黄 宇宙洪荒").unwrap();
        let plaintext = alphabet.decrypt(&key, tweak, &ciphertext).unwrap();
        assert_eq!("儖濣鈍媺惐墷礿截媃", ciphertext);
        assert_eq!("天地玄黄 宇宙洪荒", plaintext);
    }
    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        // decimal number with digits 0-9
        let radix = 10_u32;
        // the number of digits of the greatest number = radix^digits -1
        // In this case 6 decimal digits -> 999_999
        let digits = 6;

        let itg = Integer::instantiate(radix, digits).unwrap();
        let ciphertext = itg.encrypt(&key, tweak, 123_456_u64).unwrap();
        let plaintext = itg.decrypt(&key, tweak, ciphertext).unwrap();

        assert_eq!(110_655_u64, ciphertext);
        assert_eq!(123_456_u64, plaintext);
    }

    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        // decimal number with digits 0-9
        let radix = 10_u32;
        // the number of digits of the greatest number = radix^digits -1
        // In this case 6 decimal digits -> 999_999
        let digits = 6;

        let itg = Integer::instantiate(radix, digits).unwrap();
        let ciphertext = itg.encrypt(&key, tweak, 123_456_u64).unwrap();
        let plaintext = itg.decrypt(&key, tweak, ciphertext).unwrap();

        assert_eq!(110_655_u64, ciphertext);
        assert_eq!(123_456_u64, plaintext);
    }

    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        // decimal number with digits 0-9
        let radix = 10_u32;
        // the number of digits of the greatest number = radix^digits -1
        // In this case 6 decimal digits -> 999_999
        let digits = 20;

        // the value to encrypt: 10^17
        let value = BigUint::from_str_radix("100000000000000000", radix).unwrap();

        let itg = Integer::instantiate(radix, digits).unwrap();
        let ciphertext = itg.encrypt_big(&key, tweak, &value).unwrap();
        let plaintext = itg.decrypt_big(&key, tweak, &ciphertext).unwrap();

        assert_eq!(
            BigUint::from_str_radix("65348521845006160218", radix).unwrap(),
            ciphertext
        );
        assert_eq!(
            BigUint::from_str_radix("100000000000000000", radix).unwrap(),
            plaintext
        );
    }
    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        let flt = Float::instantiate().unwrap();
        let ciphertext = flt.encrypt(&key, tweak, 123_456.789_f64).unwrap();
        let plaintext = flt.decrypt(&key, tweak, ciphertext).unwrap();

        assert_eq!(1.170438892319619e91_f64, ciphertext);
        assert_eq!(123_456.789_f64, plaintext);
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
        let itg = Integer::instantiate(radix, digits)?;
        for _j in 0..10 {
            let value = rng.gen_range(0..itg.max_value.to_u64().unwrap());
            let ciphertext = itg.encrypt(&key, &[], value)?;
            assert!(ciphertext <= itg.max_value().to_u64().unwrap());
            assert_eq!(itg.decrypt(&key, &[], ciphertext)?, value);
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
            let number = Integer::instantiate(radix, digits)?;
            for _j in 0..10 {
                let exponent = rng.gen_range(0..digits - 1);
                let value = base.pow(exponent.to_u32().unwrap());
                let ciphertext = number.encrypt_big(&key, &[], &value)?;
                assert!(ciphertext <= number.max_value());
                assert_eq!(number.decrypt_big(&key, &[], &ciphertext)?, value);
            }
        }
    }

    Ok(())
}

#[test]
fn fpe_float() -> Result<(), AnoError> {
    let key = random_key();
    let mut rng = thread_rng();
    let float = Float::instantiate()?;
    for _i in 0..1000 {
        let value = rng.gen_range(0.0..f64::MAX);
        let ciphertext = float.encrypt(&key, &[], value)?;
        assert_ne!(ciphertext, value);
        assert_eq!(float.decrypt(&key, &[], ciphertext)?, value);
    }
    Ok(())
}
