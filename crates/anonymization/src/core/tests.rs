use std::collections::HashSet;

use chrono::{DateTime, Datelike, Duration, Timelike, Utc};

use super::{NumberAggregator, WordMasker};
use crate::core::{
    AnoError, HashMethod, Hasher, NoiseGenerator, NoiseMethod, WordPatternMasker, WordTokenizer,
};

#[test]
fn test_hash_sha2() -> Result<(), AnoError> {
    let hasher = Hasher {
        method: HashMethod::SHA2,
        salt: None,
    };
    let sha2_hash = hasher.apply(b"test sha2")?;
    assert_eq!(sha2_hash, "Px0txVYqBePXWF5K4xFn0Pa2mhnYA/jfsLtpIF70vJ8=");

    let hasher = Hasher {
        method: HashMethod::SHA2,
        salt: Some(b"example salt".to_vec()),
    };
    let sha2_hash_salt = hasher.apply(b"test sha2")?;
    assert_eq!(
        sha2_hash_salt,
        "d32KiG7kpZoaU2/Rqa+gbtaxDIKRA32nIxwhOXCaH1o="
    );

    Ok(())
}

#[test]
fn test_hash_sha3() -> Result<(), AnoError> {
    let hasher = Hasher {
        method: HashMethod::SHA3,
        salt: None,
    };
    let sha3_hash = hasher.apply(b"test sha3")?;
    assert_eq!(sha3_hash, "b8rRtRqnSFs8s12jsKSXHFcLf5MeHx8g6m4tvZq04/I=");

    let hasher = Hasher {
        method: HashMethod::SHA3,
        salt: Some(b"example salt".to_vec()),
    };
    let sha3_hash_salt = hasher.apply(b"test sha3")?;
    assert_eq!(
        sha3_hash_salt,
        "UBtIW7mX+cfdh3T3aPl/l465dBUbgKKZvMjZNNjwQ50="
    );

    Ok(())
}

#[test]
fn test_hash_argon2() -> Result<(), AnoError> {
    let hasher = Hasher {
        method: HashMethod::Argon2,
        salt: Some(b"example salt".to_vec()),
    };
    let argon2_hash = hasher.apply(b"low entropy data")?;
    assert_eq!(argon2_hash, "JXiQyIYJAIMZoDKhA/BOKTo+142aTkDvtITEI7NXDEM=");

    let hasher = Hasher {
        method: HashMethod::Argon2,
        salt: None, // should fail without salt
    };

    let res = hasher.apply(b"low entropy data");
    assert!(res.is_err());

    Ok(())
}

#[test]
fn test_noise_gaussian_f64() -> Result<(), AnoError> {
    let gaussian_noise_generator = NoiseGenerator::new(NoiseMethod::new_gaussian(), 10.0)?;
    let (lower_bound, upper_bound) = (40.0, 44.0);
    let noisy_data =
        gaussian_noise_generator.apply_on_float(42.0, Some(lower_bound), Some(upper_bound))?;

    assert!(noisy_data >= lower_bound && noisy_data <= upper_bound);

    Ok(())
}

#[test]
fn test_noise_laplace_f64() -> Result<(), AnoError> {
    let laplace_noise_generator = NoiseGenerator::new(NoiseMethod::new_laplace(), 10.0)?;
    let (lower_bound, upper_bound) = (40.5, 44.5);
    let noisy_data =
        laplace_noise_generator.apply_on_float(42.3, Some(lower_bound), Some(upper_bound))?;

    assert!(noisy_data >= lower_bound && noisy_data <= upper_bound);

    Ok(())
}

#[test]
fn test_noise_gaussian_i64() -> Result<(), AnoError> {
    let gaussian_noise_generator = NoiseGenerator::new(NoiseMethod::new_gaussian(), 10.0)?;
    let (lower_bound, upper_bound) = (40, 44);
    let noisy_data =
        gaussian_noise_generator.apply_on_int(42, Some(lower_bound), Some(upper_bound))?;

    assert!(noisy_data >= lower_bound && noisy_data <= upper_bound);

    Ok(())
}

#[test]
fn test_noise_laplace_i64() -> Result<(), AnoError> {
    let laplace_noise_generator = NoiseGenerator::new(NoiseMethod::new_laplace(), 10.0)?;
    let (lower_bound, upper_bound) = (40, 44);
    let noisy_data =
        laplace_noise_generator.apply_on_int(42, Some(lower_bound), Some(upper_bound))?;

    assert!(noisy_data >= lower_bound && noisy_data <= upper_bound);

    Ok(())
}

#[test]
fn test_noise_gaussian_date() -> Result<(), AnoError> {
    let std_deviation = Duration::days(10).num_seconds() as f64;
    let gaussian_noise_generator = NoiseGenerator::new(NoiseMethod::new_gaussian(), std_deviation)?;
    let noisy_date = gaussian_noise_generator.apply_on_date(
        "2023-04-07T12:34:56Z",
        Some("2023-04-07T00:00:00Z"),
        Some("2023-04-07T23:59:59Z"),
    )?;
    let date = DateTime::parse_from_rfc3339(&noisy_date)?.with_timezone(&Utc);

    assert_eq!(date.day(), 7);
    assert_eq!(date.month(), 4);
    assert_eq!(date.year(), 2023);
    Ok(())
}

#[test]
fn test_noise_laplace_date() -> Result<(), AnoError> {
    let std_deviation = Duration::days(10).num_seconds() as f64;
    let laplace_noise_generator = NoiseGenerator::new(NoiseMethod::new_laplace(), std_deviation)?;
    let noisy_date = laplace_noise_generator.apply_on_date(
        "2023-04-07T12:34:56Z",
        Some("2023-04-07T00:00:00Z"),
        Some("2023-04-07T23:59:59Z"),
    )?;
    let date = DateTime::parse_from_rfc3339(&noisy_date)?.with_timezone(&Utc);

    assert_eq!(date.day(), 7);
    assert_eq!(date.month(), 4);
    assert_eq!(date.year(), 2023);
    Ok(())
}

#[test]
fn test_mask_word() -> Result<(), AnoError> {
    // TODO: Match using https://docs.rs/aho-corasick/latest/aho_corasick/struct.AhoCorasick.html
    let input_str = String::from("Confidential: contains -secret- documents");
    let block_words = vec!["confidential", "SECRET"];
    let word_masker = WordMasker::new(&block_words);

    let safe_str = word_masker.apply(&input_str)?;

    assert_eq!(safe_str, "XXXX contains XXXX documents");
    Ok(())
}

#[test]
fn test_token_word() -> Result<(), AnoError> {
    let input_str =
        String::from("confidential: contains -secret- documents with confidential info");
    let block_words = vec!["confidential", "SECRET"];
    let word_tokenizer = WordTokenizer::new(&block_words)?;

    let safe_str = word_tokenizer.apply(&input_str)?;

    let words: HashSet<&str> = safe_str.split(' ').collect();

    assert!(!words.contains("confidential"));
    assert!(!words.contains("secret"));
    assert!(words.contains("documents"));
    Ok(())
}

#[test]
fn test_word_pattern() -> Result<(), AnoError> {
    let input_str =
        String::from("Confidential: contains -secret- documents with confidential info");
    let pattern = r"-\w+-";
    let pattern_matcher = WordPatternMasker::new(pattern)?;

    let matched_str = pattern_matcher.apply(&input_str)?;
    assert_eq!(
        matched_str,
        "Confidential: contains XXXX documents with confidential info"
    );

    let res = WordPatternMasker::new("[");
    assert!(res.is_err());

    Ok(())
}

#[test]
fn test_float_aggregation() -> Result<(), AnoError> {
    let float_aggregator = NumberAggregator::new(0.1);

    let res = float_aggregator.apply_on_float(1234.567);

    // TODO: fix float rounding issue
    assert_eq!(res, 1234.6);

    Ok(())
}

#[test]
fn test_int_aggregation() -> Result<(), AnoError> {
    let int_aggregator = NumberAggregator::new(100.0);

    let res = int_aggregator.apply_on_int(1234);

    assert_eq!(res, 1200);

    Ok(())
}

#[test]
fn test_date_aggregation() -> Result<(), AnoError> {
    let date_aggregator = NumberAggregator::new(60.0 * 60.0);

    let date_str = date_aggregator.apply_on_date("2023-04-07T12:34:56Z")?;

    let date = DateTime::parse_from_rfc3339(&date_str)?.with_timezone(&Utc);

    assert_eq!(date.day(), 7);
    assert_eq!(date.month(), 4);
    assert_eq!(date.year(), 2023);

    assert_eq!(date.hour(), 13);
    assert_eq!(date.minute(), 0);
    assert_eq!(date.second(), 0);

    Ok(())
}
