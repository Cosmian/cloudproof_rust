use chrono::{DateTime, Datelike, Duration, Utc};

use crate::core::{AnoError, HashMethod, Hasher, NoiseGenerator, NoiseMethod};

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
