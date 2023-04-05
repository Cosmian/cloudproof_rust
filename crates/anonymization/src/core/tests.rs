use crate::core::{AnoError, HashMethod, Hasher};

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
