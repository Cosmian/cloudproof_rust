use cosmian_crypto_core::{
    Aes256Gcm as Aes256GcmRust, CryptoCoreError, Dem, FixedSizeCBytes, Instantiable, Nonce,
    SymmetricKey,
};

use crate::error::AesGcmError;

/// The `encrypt` function parameters are:
///
/// Arguments:
///
/// * `key`: 32-byte array
/// * `nonce`: 12-byte array
/// * `plaintext`: the data to encrypt
/// * `authenticated_data`: an additional data that is authenticated during
///   encryption
///
/// Returns:
///
/// the ciphertext if succeeds
pub fn encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    authenticated_data: &[u8],
) -> Result<Vec<u8>, AesGcmError> {
    let key: [u8; Aes256GcmRust::KEY_LENGTH] = key
        .try_into()
        .expect("AESGCM invalid key length, expected 32 bytes");
    let nonce: [u8; Aes256GcmRust::NONCE_LENGTH] = nonce
        .try_into()
        .expect("AESGCM invalid nonce length, expected 12 bytes");

    let key =
        SymmetricKey::try_from_bytes(key).expect("could not convert key to SymmetricKey instance");
    let nonce = Nonce::try_from_bytes(nonce).expect("could not convert nonce to Nonce instance");
    Ok(Aes256GcmRust::new(&key).encrypt(&nonce, plaintext, Some(authenticated_data))?)
}

/// The `decrypt` function parameters are:
///
/// Arguments:
///
/// * `key`: 32-byte array
/// * `nonce`: 12-byte array
/// * `ciphertext`: the data to encrypt
/// * `authenticated_data`: an additional data used during encryption
///
/// Returns:
///
/// the ciphertext if succeeds
pub fn decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    authenticated_data: &[u8],
) -> Result<Vec<u8>, AesGcmError> {
    if ciphertext.len() < Aes256GcmRust::MAC_LENGTH {
        return Err(AesGcmError::CryptoCore(
            CryptoCoreError::CiphertextTooSmallError {
                ciphertext_len: ciphertext.len(),
                min: Aes256GcmRust::MAC_LENGTH as u64,
            },
        ));
    }
    let key: [u8; Aes256GcmRust::KEY_LENGTH] = key
        .try_into()
        .expect("AES256 GCM invalid key length, expected 32 bytes");
    let nonce: [u8; Aes256GcmRust::NONCE_LENGTH] = nonce
        .try_into()
        .expect("AES256 GCM invalid nonce length, expected 12 bytes");

    let key =
        SymmetricKey::try_from_bytes(key).expect("could not convert key to SymmetricKey instance");
    let nonce = Nonce::try_from_bytes(nonce).expect("could not convert nonce to Nonce instance");
    Ok(Aes256GcmRust::new(&key).decrypt(&nonce, ciphertext, Some(authenticated_data))?)
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::Aes256Gcm;

    use crate::core::aesgcm::{decrypt, encrypt};

    #[test]
    fn test_encrypt_decrypt() {
        let key = vec![42_u8; Aes256Gcm::KEY_LENGTH];
        let nonce = vec![42_u8; Aes256Gcm::NONCE_LENGTH];
        let plaintext = b"plaintext";
        let authenticated_data = b"authenticated_data";
        let ciphertext = encrypt(&key, &nonce, plaintext, authenticated_data).unwrap();
        let cleartext = decrypt(&key, &nonce, &ciphertext, authenticated_data).unwrap();
        assert_eq!(plaintext.to_vec(), cleartext);
    }
}
