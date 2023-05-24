use std::collections::HashSet;

use approx::assert_relative_eq;
use chrono::{DateTime, Datelike, Timelike};

use super::{NumberAggregator, WordMasker};
use crate::core::{
    AnoError, DateAggregator, HashMethod, Hasher, NoiseGenerator, NumberScaler, TimeUnit,
    WordPatternMasker, WordTokenizer,
};

#[test]
fn test_hash_sha2() -> Result<(), AnoError> {
    let hasher = Hasher::new(HashMethod::SHA2(None));
    let sha2_hash = hasher.apply(b"test sha2")?;
    assert_eq!(sha2_hash, "Px0txVYqBePXWF5K4xFn0Pa2mhnYA/jfsLtpIF70vJ8=");

    let hasher = Hasher::new(HashMethod::SHA2(Some(b"example salt".to_vec())));
    let sha2_hash_salt = hasher.apply(b"test sha2")?;
    assert_eq!(
        sha2_hash_salt,
        "d32KiG7kpZoaU2/Rqa+gbtaxDIKRA32nIxwhOXCaH1o="
    );

    Ok(())
}

#[test]
fn test_hash_sha3() -> Result<(), AnoError> {
    let hasher = Hasher::new(HashMethod::SHA3(None));
    let sha3_hash = hasher.apply(b"test sha3")?;
    assert_eq!(sha3_hash, "b8rRtRqnSFs8s12jsKSXHFcLf5MeHx8g6m4tvZq04/I=");

    let hasher = Hasher::new(HashMethod::SHA3(Some(b"example salt".to_vec())));
    let sha3_hash_salt = hasher.apply(b"test sha3")?;
    assert_eq!(
        sha3_hash_salt,
        "UBtIW7mX+cfdh3T3aPl/l465dBUbgKKZvMjZNNjwQ50="
    );

    Ok(())
}

#[test]
fn test_hash_argon2() -> Result<(), AnoError> {
    let hasher = Hasher::new(HashMethod::Argon2(b"example salt".to_vec()));
    let argon2_hash = hasher.apply(b"low entropy data")?;
    assert_eq!(argon2_hash, "JXiQyIYJAIMZoDKhA/BOKTo+142aTkDvtITEI7NXDEM=");

    Ok(())
}

#[test]
fn test_noise_gaussian_f64() -> Result<(), AnoError> {
    let gaussian_noise_generator = NoiseGenerator::new_with_parameters("Gaussian", 0.0, 1.0)?;
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
    let res = NoiseGenerator::new_with_parameters("Uniform", 0.0, 2.0);
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
    let input_datestr = "2023-04-07T12:34:56Z";
    let output_datestr = gaussian_noise_generator.apply_on_date(input_datestr)?;
    let output_date = DateTime::parse_from_rfc3339(&output_datestr)?;

    assert_eq!(output_date.day(), 7);
    assert_eq!(output_date.month(), 4);
    assert_eq!(output_date.year(), 2023);
    // Check that the output date has the same timezone as the input
    assert_eq!(
        output_date.timezone(),
        DateTime::parse_from_rfc3339(input_datestr)?.timezone()
    );

    let res = gaussian_noise_generator.apply_on_date("AAAA");
    assert!(res.is_err());
    Ok(())
}

#[test]
fn test_noise_laplace_date() -> Result<(), AnoError> {
    let laplace_noise_generator =
        NoiseGenerator::new_with_parameters("Laplace", 0.0, 2.0 * 3600.0)?;
    let input_datestr = "2023-04-07T12:34:56+05:00";
    let output_datestr = laplace_noise_generator.apply_on_date(input_datestr)?;
    let output_date = DateTime::parse_from_rfc3339(&output_datestr)?;

    assert_eq!(output_date.day(), 7);
    assert_eq!(output_date.month(), 4);
    assert_eq!(output_date.year(), 2023);
    // Check that the output date has the same timezone as the input
    assert_eq!(
        output_date.timezone(),
        DateTime::parse_from_rfc3339(input_datestr)?.timezone()
    );
    Ok(())
}

#[test]
fn test_noise_uniform_date() -> Result<(), AnoError> {
    // generate noise between -10h and +10h
    let uniform_noise_generator =
        NoiseGenerator::new_with_bounds("Uniform", -10.0 * 3600.0, 10.0 * 3600.0)?;
    let input_datestr = "2023-04-07T12:34:56-03:00";
    let output_datestr = uniform_noise_generator.apply_on_date(input_datestr)?;
    let output_date = DateTime::parse_from_rfc3339(&output_datestr)?;

    assert_eq!(output_date.day(), 7);
    assert_eq!(output_date.month(), 4);
    assert_eq!(output_date.year(), 2023);
    // Check that the output date has the same timezone as the input
    assert_eq!(
        output_date.timezone(),
        DateTime::parse_from_rfc3339(input_datestr)?.timezone()
    );
    Ok(())
}

#[test]
fn test_correlated_noise_gaussian_f64() -> Result<(), AnoError> {
    let noise_generator = NoiseGenerator::new_with_parameters("Gaussian", 10.0, 2.0)?;
    let values = vec![1.0, 1.0, 1.0];
    let factors = vec![1.0, 2.0, 4.0];
    let noisy_values = noise_generator.apply_correlated_noise_on_floats(&values, &factors)?;
    assert_relative_eq!(
        (noisy_values[0] - values[0]) * factors[1],
        (noisy_values[1] - values[1]) * factors[0],
        epsilon = 1e-6
    );
    assert_relative_eq!(
        (noisy_values[0] - values[0]) * factors[2],
        (noisy_values[2] - values[2]) * factors[0],
        epsilon = 1e-6
    );
    // Ordering only holds if noise is positive
    assert!(noisy_values[0] < noisy_values[1]);
    assert!(noisy_values[1] < noisy_values[2]);
    Ok(())
}

#[test]
fn test_correlated_noise_laplace_i64() -> Result<(), AnoError> {
    let noise_generator = NoiseGenerator::new_with_parameters("Laplace", 10.0, 2.0)?;
    let values = vec![1, 1, 1];
    let factors = vec![1.0, 2.0, 4.0];
    let noisy_values = noise_generator.apply_correlated_noise_on_ints(&values, &factors)?;
    // Ordering only holds if noise is positive
    assert!(noisy_values[0] <= noisy_values[1]);
    assert!(noisy_values[1] <= noisy_values[2]);
    Ok(())
}

#[test]
fn test_correlated_noise_uniform_date() -> Result<(), AnoError> {
    let noise_generator = NoiseGenerator::new_with_bounds("Uniform", 0.0, 10.0)?;
    let values = vec![
        "2023-05-02T00:00:00-05:00",
        "2023-05-02T00:00:00+00:00",
        "2023-05-02T00:00:00Z",
    ];
    let factors = vec![1.0, 2.0, 4.0];
    let noisy_values = noise_generator.apply_correlated_noise_on_dates(&values, &factors)?;

    let date1 = DateTime::parse_from_rfc3339(&noisy_values[0])?;
    let date2 = DateTime::parse_from_rfc3339(&noisy_values[1])?;
    let date3 = DateTime::parse_from_rfc3339(&noisy_values[2])?;
    // Ordering only holds if noise is positive
    assert!(date1.second() <= date2.second());
    assert!(date2.second() <= date3.second());

    // Check that the output date has the same timezone as the input
    assert_eq!(
        date1.timezone(),
        DateTime::parse_from_rfc3339(values[0])?.timezone()
    );
    assert_eq!(date2.timezone(), date3.timezone());
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

    let matched_str = pattern_matcher.apply(&input_str);
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
    let float_aggregator = NumberAggregator::new(-1)?;
    let res = float_aggregator.apply_on_float(1234.567);
    assert_eq!(res, "1234.6");

    let float_aggregator = NumberAggregator::new(2)?;
    let res = float_aggregator.apply_on_float(1234.567);
    assert_eq!(res, "1200");

    let float_aggregator = NumberAggregator::new(10)?;
    let res = float_aggregator.apply_on_float(1234.567);
    assert_eq!(res, "0");

    let float_aggregator = NumberAggregator::new(-10)?;
    let res = float_aggregator.apply_on_float(1234.567);
    assert_eq!(res, "1234.5670000000");

    let res = NumberAggregator::new(309);
    assert!(res.is_err());

    Ok(())
}

#[test]
fn test_int_aggregation() -> Result<(), AnoError> {
    let int_aggregator = NumberAggregator::new(2)?;
    let res = int_aggregator.apply_on_int(1234);
    assert_eq!(res, "1200");

    let int_aggregator = NumberAggregator::new(-2)?;
    let res = int_aggregator.apply_on_int(1234);
    assert_eq!(res, "1234");

    Ok(())
}

#[test]
fn test_time_aggregation() -> Result<(), AnoError> {
    let time_aggregator = DateAggregator::new(TimeUnit::Hour);
    let input_datestr = "2023-04-07T12:34:56+02:00";
    let output_datestr = time_aggregator.apply_on_date(input_datestr)?;
    let output_date = DateTime::parse_from_rfc3339(&output_datestr)?;

    assert_eq!(output_date.day(), 7);
    assert_eq!(output_date.month(), 4);
    assert_eq!(output_date.year(), 2023);

    assert_eq!(output_date.hour(), 12);
    assert_eq!(output_date.minute(), 0);
    assert_eq!(output_date.second(), 0);

    // Check that the output date has the same timezone as the input
    assert_eq!(
        output_date.timezone(),
        DateTime::parse_from_rfc3339(input_datestr)?.timezone()
    );

    let res = time_aggregator.apply_on_date("AAAA");
    assert!(res.is_err());

    Ok(())
}

#[test]
fn test_date_aggregation() -> Result<(), AnoError> {
    let date_aggregator = DateAggregator::new(TimeUnit::Month);
    let input_datestr = "2023-04-07T12:34:56-05:00";
    let output_datestr = date_aggregator.apply_on_date(input_datestr)?;
    let output_date = DateTime::parse_from_rfc3339(&output_datestr)?;

    assert_eq!(output_date.day(), 1);
    assert_eq!(output_date.month(), 4);
    assert_eq!(output_date.year(), 2023);

    assert_eq!(output_date.hour(), 0);
    assert_eq!(output_date.minute(), 0);
    assert_eq!(output_date.second(), 0);

    // Check that the output date has the same timezone as the input
    assert_eq!(
        output_date.timezone(),
        DateTime::parse_from_rfc3339(input_datestr)?.timezone()
    );

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
