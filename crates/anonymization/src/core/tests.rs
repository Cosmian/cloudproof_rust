use std::collections::HashSet;

use chrono::{DateTime, Datelike, Timelike, Utc};

use super::{NumberAggregator, WordMasker};
use crate::core::{
    AnoError, DateAggregator, HashMethod, Hasher, NoiseGenerator, NumberScaler, WordPatternMasker,
    WordTokenizer,
};

#[test]
fn test_hash_sha2() -> Result<(), AnoError> {
    let hasher = Hasher::new(HashMethod::SHA2, None)?;
    let sha2_hash = hasher.apply(b"test sha2")?;
    assert_eq!(sha2_hash, "Px0txVYqBePXWF5K4xFn0Pa2mhnYA/jfsLtpIF70vJ8=");

    let hasher = Hasher::new(HashMethod::SHA2, Some(b"example salt".to_vec()))?;
    let sha2_hash_salt = hasher.apply(b"test sha2")?;
    assert_eq!(
        sha2_hash_salt,
        "d32KiG7kpZoaU2/Rqa+gbtaxDIKRA32nIxwhOXCaH1o="
    );

    Ok(())
}

#[test]
fn test_hash_sha3() -> Result<(), AnoError> {
    let hasher = Hasher::new(HashMethod::SHA3, None)?;
    let sha3_hash = hasher.apply(b"test sha3")?;
    assert_eq!(sha3_hash, "b8rRtRqnSFs8s12jsKSXHFcLf5MeHx8g6m4tvZq04/I=");

    let hasher = Hasher::new(HashMethod::SHA3, Some(b"example salt".to_vec()))?;
    let sha3_hash_salt = hasher.apply(b"test sha3")?;
    assert_eq!(
        sha3_hash_salt,
        "UBtIW7mX+cfdh3T3aPl/l465dBUbgKKZvMjZNNjwQ50="
    );

    Ok(())
}

#[test]
fn test_hash_argon2() -> Result<(), AnoError> {
    let hasher = Hasher::new(HashMethod::Argon2, Some(b"example salt".to_vec()))?;
    let argon2_hash = hasher.apply(b"low entropy data")?;
    assert_eq!(argon2_hash, "JXiQyIYJAIMZoDKhA/BOKTo+142aTkDvtITEI7NXDEM=");

    let res = Hasher::new(
        HashMethod::Argon2,
        None, // should fail without salt
    );
    assert!(res.is_err());

    Ok(())
}

#[test]
fn test_noise_gaussian_f64() -> Result<(), AnoError> {
    let gaussian_noise_generator = NoiseGenerator::new_with_parameters("Gaussian", 0.0, 2.0)?;
    let noisy_data = gaussian_noise_generator.apply_on_float(40.0)?;
    assert!((30.0..=50.0).contains(&noisy_data));

    let gaussian_noise_generator = NoiseGenerator::new_with_bounds("Gaussian", -5.0, 5.0)?;
    let noisy_data = gaussian_noise_generator.apply_on_float(40.0)?;
    assert!((30.0..=50.0).contains(&noisy_data));

    let res = NoiseGenerator::new_with_parameters("Gaussian", 0.0, -1.0);
    assert!(res.is_err());

    let res = NoiseGenerator::new_with_bounds("Gaussian", 1.0, 0.0);
    assert!(res.is_err());

    Ok(())
}

#[test]
fn test_noise_laplace_f64() -> Result<(), AnoError> {
    let laplace_noise_generator = NoiseGenerator::new_with_parameters("Laplace", 0.0, 1.0)?;
    let noisy_data = laplace_noise_generator.apply_on_float(40.0)?;
    assert!((30.0..=50.0).contains(&noisy_data));

    let laplace_noise_generator = NoiseGenerator::new_with_bounds("Laplace", -10.0, 10.0)?;
    let noisy_data = laplace_noise_generator.apply_on_float(40.0)?;
    assert!((30.0..=50.0).contains(&noisy_data));

    Ok(())
}

#[test]
fn test_noise_uniform_f64() -> Result<(), AnoError> {
    let res = NoiseGenerator::new_with_parameters("Uniform", 0.0, 1.0);
    assert!(res.is_err());

    let laplace_noise_generator = NoiseGenerator::new_with_bounds("Uniform", -10.0, 10.0)?;
    let noisy_data = laplace_noise_generator.apply_on_float(40.0)?;
    assert!((30.0..=50.0).contains(&noisy_data));

    Ok(())
}

#[test]
fn test_noise_gaussian_i64() -> Result<(), AnoError> {
    let gaussian_noise_generator = NoiseGenerator::new_with_parameters("Gaussian", 0.0, 1.0)?;
    let noisy_data = gaussian_noise_generator.apply_on_int(40)?;
    assert!((30..=50).contains(&noisy_data));

    let gaussian_noise_generator = NoiseGenerator::new_with_bounds("Gaussian", -5.0, 5.0)?;
    let noisy_data = gaussian_noise_generator.apply_on_int(40)?;
    assert!((30..=50).contains(&noisy_data));

    Ok(())
}

#[test]
fn test_noise_laplace_i64() -> Result<(), AnoError> {
    let laplace_noise_generator = NoiseGenerator::new_with_parameters("Laplace", 0.0, 1.0)?;
    let noisy_data = laplace_noise_generator.apply_on_int(40)?;
    assert!((30..=50).contains(&noisy_data));

    let laplace_noise_generator = NoiseGenerator::new_with_bounds("Laplace", -10.0, 10.0)?;
    let noisy_data = laplace_noise_generator.apply_on_int(40)?;
    assert!((30..=50).contains(&noisy_data));

    Ok(())
}

#[test]
fn test_noise_uniform_i64() -> Result<(), AnoError> {
    let laplace_noise_generator = NoiseGenerator::new_with_bounds("Uniform", -10.0, 10.0)?;
    let noisy_data = laplace_noise_generator.apply_on_int(40)?;
    assert!((30..=50).contains(&noisy_data));

    Ok(())
}

#[test]
fn test_noise_gaussian_date() -> Result<(), AnoError> {
    let gaussian_noise_generator =
        NoiseGenerator::new_with_parameters("Gaussian", 0.0, 2.0 * 3600.0)?;
    let noisy_date = gaussian_noise_generator.apply_on_date("2023-04-07T12:34:56Z")?;
    let date = DateTime::parse_from_rfc3339(&noisy_date)?.with_timezone(&Utc);

    assert_eq!(date.day(), 7);
    assert_eq!(date.month(), 4);
    assert_eq!(date.year(), 2023);
    Ok(())
}

#[test]
fn test_noise_laplace_date() -> Result<(), AnoError> {
    let laplace_noise_generator =
        NoiseGenerator::new_with_parameters("Laplace", 0.0, 2.0 * 3600.0)?;
    let noisy_date = laplace_noise_generator.apply_on_date("2023-04-07T12:34:56Z")?;
    let date = DateTime::parse_from_rfc3339(&noisy_date)?.with_timezone(&Utc);

    assert_eq!(date.day(), 7);
    assert_eq!(date.month(), 4);
    assert_eq!(date.year(), 2023);
    Ok(())
}

#[test]
fn test_noise_uniform_date() -> Result<(), AnoError> {
    // generate noise between -10h and +10h
    let uniform_noise_generator =
        NoiseGenerator::new_with_bounds("Uniform", -10.0 * 3600.0, 10.0 * 3600.0)?;
    let noisy_date = uniform_noise_generator.apply_on_date("2023-04-07T12:34:56Z")?;
    let date = DateTime::parse_from_rfc3339(&noisy_date)?.with_timezone(&Utc);

    assert_eq!(date.day(), 7);
    assert_eq!(date.month(), 4);
    assert_eq!(date.year(), 2023);
    Ok(())
}

#[test]
fn test_correlated_noise_gaussian_f64() -> Result<(), AnoError> {
    let gaussian_noise_generator = NoiseGenerator::new_with_parameters("Gaussian", 10.0, 2.0)?;
    let values = vec![1.0, 1.0, 1.0];
    let factors = vec![1.0, 2.0, 4.0];
    let noisy_values = gaussian_noise_generator.apply_correlated_noise(&values, &factors)?;
    assert_eq!(
        (noisy_values[0] - values[0]) / factors[0],
        (noisy_values[1] - values[1]) / factors[1]
    );
    assert_eq!(
        (noisy_values[0] - values[0]) / factors[0],
        (noisy_values[2] - values[2]) / factors[2]
    );
    // Ordering only holds if noise is positive
    assert!(noisy_values[0] < noisy_values[1]);
    assert!(noisy_values[1] < noisy_values[2]);
    Ok(())
}
#[test]
fn test_mask_word() -> Result<(), AnoError> {
    let input_str = String::from("Confidential: contains -secret- documents");
    let block_words = vec!["confidential", "SECRET"];
    let word_masker = WordMasker::new(&block_words);

    let safe_str = word_masker.apply(&input_str)?;

    assert_eq!(safe_str, "XXXX: contains -XXXX- documents");
    Ok(())
}

#[test]
fn test_token_word() -> Result<(), AnoError> {
    let input_str = String::from("confidential : contains secret documents with confidential info");
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
    let pattern_matcher = WordPatternMasker::new(pattern, "####")?;

    let matched_str = pattern_matcher.apply(&input_str)?;
    assert_eq!(
        matched_str,
        "Confidential: contains #### documents with confidential info"
    );

    let res = WordPatternMasker::new("[", "####");
    assert!(res.is_err());

    Ok(())
}

#[test]
fn test_float_aggregation() -> Result<(), AnoError> {
    let float_aggregator = NumberAggregator::new(-1);
    let res = float_aggregator.apply_on_float(1234.567);
    assert_eq!(res, "1234.6");

    let float_aggregator = NumberAggregator::new(2);
    let res = float_aggregator.apply_on_float(1234.567);
    assert_eq!(res, "1200");

    let float_aggregator = NumberAggregator::new(10);
    let res = float_aggregator.apply_on_float(1234.567);
    assert_eq!(res, "0");

    let float_aggregator = NumberAggregator::new(-10);
    let res = float_aggregator.apply_on_float(1234.567);
    assert_eq!(res, "1234.5670000000");

    Ok(())
}

#[test]
fn test_int_aggregation() -> Result<(), AnoError> {
    let int_aggregator = NumberAggregator::new(2);
    let res = int_aggregator.apply_on_int(1234);
    assert_eq!(res, "1200");

    let int_aggregator = NumberAggregator::new(-2);
    let res = int_aggregator.apply_on_int(1234);
    assert_eq!(res, "1234");

    Ok(())
}

#[test]
fn test_time_aggregation() -> Result<(), AnoError> {
    let time_aggregator = DateAggregator::new("Hour");
    let date_str = time_aggregator.apply_on_date("2023-04-07T12:34:56Z")?;
    let date = DateTime::parse_from_rfc3339(&date_str)?.with_timezone(&Utc);

    assert_eq!(date.day(), 7);
    assert_eq!(date.month(), 4);
    assert_eq!(date.year(), 2023);

    assert_eq!(date.hour(), 12);
    assert_eq!(date.minute(), 0);
    assert_eq!(date.second(), 0);

    Ok(())
}

#[test]
fn test_date_aggregation() -> Result<(), AnoError> {
    let date_aggregator = DateAggregator::new("Month");
    let date_str = date_aggregator.apply_on_date("2023-04-07T12:34:56Z")?;
    let date = DateTime::parse_from_rfc3339(&date_str)?.with_timezone(&Utc);

    assert_eq!(date.day(), 1);
    assert_eq!(date.month(), 4);
    assert_eq!(date.year(), 2023);

    assert_eq!(date.hour(), 0);
    assert_eq!(date.minute(), 0);
    assert_eq!(date.second(), 0);

    Ok(())
}

#[test]
fn test_float_scale() {
    let float_scaler = NumberScaler::new(10.0, 5.0, 2.0, -50.0);

    let n1 = float_scaler.apply_on_float(20.0);
    let n2 = float_scaler.apply_on_float(19.5);

    assert!(n1 > n2);
}

#[test]
fn test_int_scale() {
    let int_scaler = NumberScaler::new(10.0, 5.0, 20.0, -50.0);

    let n1 = int_scaler.apply_on_int(20);
    let n2 = int_scaler.apply_on_int(19);

    assert!(n1 >= n2);
}
