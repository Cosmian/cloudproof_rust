use std::collections::HashSet;

use approx::assert_relative_eq;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Datelike, Timelike, Utc};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

use super::hash::Hasher;
use crate::wasm_bindgen::{
    noise::{NoiseGeneratorWithBounds, NoiseGeneratorWithParameters},
    number::{DateAggregator, NumberAggregator, NumberScaler},
    word::{WordMasker, WordPatternMasker, WordTokenizer},
};

#[wasm_bindgen_test]
fn test_hash() -> Result<(), JsValue> {
    let sha2_hash = Hasher::new("SHA2", None)?.apply_str("test sha2")?;
    let sha2_hash_from_data_in_bytes = Hasher::new("SHA2", None)?.apply_bytes(b"test sha2")?;
    assert_eq!(sha2_hash, "Px0txVYqBePXWF5K4xFn0Pa2mhnYA/jfsLtpIF70vJ8=");
    assert_eq!(
        "Px0txVYqBePXWF5K4xFn0Pa2mhnYA/jfsLtpIF70vJ8=",
        general_purpose::STANDARD.encode(sha2_hash_from_data_in_bytes.to_vec())
    );

    let sha2_hash_with_salt =
        Hasher::new("SHA2", Some(b"example salt".to_vec()))?.apply_str("test sha2")?;
    assert_eq!(
        sha2_hash_with_salt,
        "d32KiG7kpZoaU2/Rqa+gbtaxDIKRA32nIxwhOXCaH1o="
    );

    let sha3_hash = Hasher::new("SHA3", None)?.apply_str("test sha3")?;
    assert_eq!(sha3_hash, "b8rRtRqnSFs8s12jsKSXHFcLf5MeHx8g6m4tvZq04/I=");

    let sha3_hash_with_salt =
        Hasher::new("SHA3", Some(b"example salt".to_vec()))?.apply_str("test sha3")?;
    assert_eq!(
        sha3_hash_with_salt,
        "UBtIW7mX+cfdh3T3aPl/l465dBUbgKKZvMjZNNjwQ50="
    );

    let argon2_hash_with_salt =
        Hasher::new("Argon2", Some(b"example salt".to_vec()))?.apply_str("low entropy data")?;
    assert_eq!(
        argon2_hash_with_salt,
        "JXiQyIYJAIMZoDKhA/BOKTo+142aTkDvtITEI7NXDEM="
    );
    Ok(())
}

#[wasm_bindgen_test]
fn test_noise_gaussian_f64() -> Result<(), JsValue> {
    let mut gaussian_noise_generator = NoiseGeneratorWithParameters::new("Gaussian", 0.0, 1.0)?;
    let noisy_data = gaussian_noise_generator.apply_on_float(40.0);
    assert!((30.0..=50.0).contains(&noisy_data));

    let mut gaussian_noise_generator = NoiseGeneratorWithBounds::new("Gaussian", -5.0, 5.0)?;
    let noisy_data = gaussian_noise_generator.apply_on_float(40.0);
    assert!((30.0..=50.0).contains(&noisy_data));

    let res = NoiseGeneratorWithParameters::new("Gaussian", 0.0, -1.0);
    assert!(res.is_err());

    let res = NoiseGeneratorWithBounds::new("Gaussian", 1.0, 0.0);
    assert!(res.is_err());

    Ok(())
}

#[wasm_bindgen_test]
fn test_noise_laplace_f64() -> Result<(), JsValue> {
    let mut laplace_noise_generator = NoiseGeneratorWithParameters::new("Laplace", 0.0, 1.0)?;
    let noisy_data = laplace_noise_generator.apply_on_float(40.0);
    assert!((30.0..=50.0).contains(&noisy_data));

    let mut laplace_noise_generator = NoiseGeneratorWithBounds::new("Laplace", -10.0, 10.0)?;
    let noisy_data = laplace_noise_generator.apply_on_float(40.0);
    assert!((30.0..=50.0).contains(&noisy_data));

    Ok(())
}

#[wasm_bindgen_test]
fn test_noise_uniform_f64() -> Result<(), JsValue> {
    let res = NoiseGeneratorWithParameters::new("Uniform", 0.0, 2.0);
    assert!(res.is_err());

    let mut laplace_noise_generator = NoiseGeneratorWithBounds::new("Uniform", -10.0, 10.0)?;
    let noisy_data = laplace_noise_generator.apply_on_float(40.0);
    assert!((30.0..=50.0).contains(&noisy_data));

    Ok(())
}

#[wasm_bindgen_test]
fn test_noise_gaussian_i64() -> Result<(), JsValue> {
    let mut gaussian_noise_generator = NoiseGeneratorWithParameters::new("Gaussian", 0.0, 1.0)?;
    let noisy_data = gaussian_noise_generator.apply_on_int(40);
    assert!((30..=50).contains(&noisy_data));

    let mut gaussian_noise_generator = NoiseGeneratorWithBounds::new("Gaussian", -5.0, 5.0)?;
    let noisy_data = gaussian_noise_generator.apply_on_int(40);
    assert!((30..=50).contains(&noisy_data));

    Ok(())
}

#[wasm_bindgen_test]
fn test_noise_laplace_i64() -> Result<(), JsValue> {
    let mut laplace_noise_generator = NoiseGeneratorWithParameters::new("Laplace", 0.0, 1.0)?;
    let noisy_data = laplace_noise_generator.apply_on_int(40);
    assert!((30..=50).contains(&noisy_data));

    let mut laplace_noise_generator = NoiseGeneratorWithBounds::new("Laplace", -10.0, 10.0)?;
    let noisy_data = laplace_noise_generator.apply_on_int(40);
    assert!((30..=50).contains(&noisy_data));

    Ok(())
}

#[wasm_bindgen_test]
fn test_noise_uniform_i64() -> Result<(), JsValue> {
    let mut laplace_noise_generator = NoiseGeneratorWithBounds::new("Uniform", -10.0, 10.0)?;
    let noisy_data = laplace_noise_generator.apply_on_int(40);
    assert!((30..=50).contains(&noisy_data));

    Ok(())
}

#[wasm_bindgen_test]
fn test_noise_gaussian_date() -> Result<(), JsValue> {
    let mut gaussian_noise_generator =
        NoiseGeneratorWithParameters::new("Gaussian", 0.0, 2.0 * 3600.0)?;
    let noisy_date = gaussian_noise_generator.apply_on_date("2023-04-07T12:34:56Z")?;
    let date = DateTime::parse_from_rfc3339(&noisy_date)
        .unwrap()
        .with_timezone(&Utc);

    assert_eq!(date.day(), 7);
    assert_eq!(date.month(), 4);
    assert_eq!(date.year(), 2023);

    let res = gaussian_noise_generator.apply_on_date("AAAA");
    assert!(res.is_err());
    Ok(())
}

#[wasm_bindgen_test]
fn test_noise_laplace_date() -> Result<(), JsValue> {
    let mut laplace_noise_generator =
        NoiseGeneratorWithParameters::new("Laplace", 0.0, 2.0 * 3600.0)?;
    let noisy_date = laplace_noise_generator.apply_on_date("2023-04-07T12:34:56Z")?;
    let date = DateTime::parse_from_rfc3339(&noisy_date)
        .unwrap()
        .with_timezone(&Utc);

    assert_eq!(date.day(), 7);
    assert_eq!(date.month(), 4);
    assert_eq!(date.year(), 2023);
    Ok(())
}

#[wasm_bindgen_test]
fn test_noise_uniform_date() -> Result<(), JsValue> {
    // generate noise between -10h and +10h
    let mut uniform_noise_generator =
        NoiseGeneratorWithBounds::new("Uniform", -10.0 * 3600.0, 10.0 * 3600.0)?;
    let noisy_date = uniform_noise_generator.apply_on_date("2023-04-07T12:34:56Z")?;
    let date = DateTime::parse_from_rfc3339(&noisy_date)
        .unwrap()
        .with_timezone(&Utc);

    assert_eq!(date.day(), 7);
    assert_eq!(date.month(), 4);
    assert_eq!(date.year(), 2023);
    Ok(())
}

#[wasm_bindgen_test]
fn test_correlated_noise_gaussian_f64() -> Result<(), JsValue> {
    let mut noise_generator = NoiseGeneratorWithParameters::new("Gaussian", 10.0, 2.0)?;
    let values = vec![1.0, 1.0, 1.0];
    let factors = vec![1.0, 2.0, 4.0];
    let noisy_values =
        noise_generator.apply_correlated_noise_on_floats(values.clone(), factors.clone());
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

#[wasm_bindgen_test]
fn test_correlated_noise_laplace_i64() -> Result<(), JsValue> {
    let mut noise_generator = NoiseGeneratorWithParameters::new("Laplace", 10.0, 2.0)?;
    let values = vec![1, 1, 1];
    let factors = vec![1.0, 2.0, 4.0];
    let noisy_values = noise_generator.apply_correlated_noise_on_ints(values, factors);
    // Ordering only holds if noise is positive
    assert!(noisy_values[0] <= noisy_values[1]);
    assert!(noisy_values[1] <= noisy_values[2]);
    Ok(())
}

#[wasm_bindgen_test]
fn test_correlated_noise_uniform_date() -> Result<(), JsValue> {
    let mut noise_generator = NoiseGeneratorWithBounds::new("Uniform", 0.0, 10.0)?;
    let values = vec![
        "2023-05-02T00:00:00Z",
        "2023-05-02T00:00:00Z",
        "2023-05-02T00:00:00Z",
    ]
    .join(";");
    let factors = vec![1.0, 2.0, 4.0];
    let noisy_values: Vec<String> = noise_generator
        .apply_correlated_noise_on_dates(values, factors)?
        .split(';')
        .map(std::string::ToString::to_string)
        .collect();

    let date1 = DateTime::parse_from_rfc3339(&noisy_values[0])
        .unwrap()
        .with_timezone(&Utc);
    let date2 = DateTime::parse_from_rfc3339(&noisy_values[1])
        .unwrap()
        .with_timezone(&Utc);
    let date3 = DateTime::parse_from_rfc3339(&noisy_values[2])
        .unwrap()
        .with_timezone(&Utc);
    // Ordering only holds if noise is positive
    assert!(date1.second() <= date2.second());
    assert!(date2.second() <= date3.second());
    Ok(())
}

#[wasm_bindgen_test]
fn test_mask_word() -> Result<(), JsValue> {
    let input_str = String::from("Confidential: contains -secret- documents");
    let block_words = vec!["confidential", "SECRET"].join(";");
    let word_masker = WordMasker::new(block_words);

    let safe_str = word_masker.apply(&input_str);

    assert_eq!(safe_str, "XXXX: contains -XXXX- documents");
    Ok(())
}

#[wasm_bindgen_test]
fn test_token_word() -> Result<(), JsValue> {
    let input_str = String::from("confidential : contains secret documents with confidential info");
    let block_words = vec!["confidential", "SECRET"].join(";");
    let word_tokenizer = WordTokenizer::new(block_words)?;

    let safe_str = word_tokenizer.apply(&input_str);

    let words: HashSet<&str> = safe_str.split(' ').collect();
    assert!(!words.contains("confidential"));
    assert!(!words.contains("secret"));
    assert!(words.contains("documents"));
    Ok(())
}

#[wasm_bindgen_test]
fn test_word_pattern() -> Result<(), JsValue> {
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

#[wasm_bindgen_test]
fn test_float_aggregation() -> Result<(), JsValue> {
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

#[wasm_bindgen_test]
fn test_int_aggregation() -> Result<(), JsValue> {
    let int_aggregator = NumberAggregator::new(2)?;
    let res = int_aggregator.apply_on_int(1234);
    assert_eq!(res, "1200");

    let int_aggregator = NumberAggregator::new(-2)?;
    let res = int_aggregator.apply_on_int(1234);
    assert_eq!(res, "1234");

    Ok(())
}

#[wasm_bindgen_test]
fn test_time_aggregation() -> Result<(), JsValue> {
    let time_aggregator = DateAggregator::new("Hour")?;
    let date_str = time_aggregator.apply_on_date("2023-04-07T12:34:56Z")?;
    let date = DateTime::parse_from_rfc3339(&date_str)
        .unwrap()
        .with_timezone(&Utc);

    assert_eq!(date.day(), 7);
    assert_eq!(date.month(), 4);
    assert_eq!(date.year(), 2023);

    assert_eq!(date.hour(), 12);
    assert_eq!(date.minute(), 0);
    assert_eq!(date.second(), 0);

    let res = time_aggregator.apply_on_date("AAAA");
    assert!(res.is_err());

    Ok(())
}

#[wasm_bindgen_test]
fn test_date_aggregation() -> Result<(), JsValue> {
    let date_aggregator = DateAggregator::new("Month")?;
    let date_str = date_aggregator.apply_on_date("2023-04-07T12:34:56Z")?;
    let date = DateTime::parse_from_rfc3339(&date_str)
        .unwrap()
        .with_timezone(&Utc);

    assert_eq!(date.day(), 1);
    assert_eq!(date.month(), 4);
    assert_eq!(date.year(), 2023);

    assert_eq!(date.hour(), 0);
    assert_eq!(date.minute(), 0);
    assert_eq!(date.second(), 0);

    Ok(())
}

#[wasm_bindgen_test]
fn test_float_scale() {
    let float_scaler = NumberScaler::new(10.0, 5.0, 2.0, -50.0);

    let n1 = float_scaler.apply_on_float(20.0);
    let n2 = float_scaler.apply_on_float(19.5);

    assert!(n1 > n2);
}

#[wasm_bindgen_test]
fn test_int_scale() {
    let int_scaler = NumberScaler::new(10.0, 5.0, 20.0, -50.0);

    let n1 = int_scaler.apply_on_int(20);
    let n2 = int_scaler.apply_on_int(19);

    assert!(n1 >= n2);
}
