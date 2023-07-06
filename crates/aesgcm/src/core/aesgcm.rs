use cloudproof_cover_crypt::reexport::crypto_core::{
    reexport::rand_core::SeedableRng, Aes256Gcm as Aes256GcmRust, CryptoCoreError, CsRng, Dem,
    FixedSizeCBytes, Instantiable, Nonce, RandomFixedSizeCBytes, SymmetricKey,
};

use crate::error::AesGcmError;

pub const BLOCK_LENGTH: usize = 16;

const ENCRYPTION_OVERHEAD: usize = Aes256GcmRust::NONCE_LENGTH + Aes256GcmRust::MAC_LENGTH;

pub fn encrypt(
    key: [u8; Aes256GcmRust::KEY_LENGTH],
    plaintext: &[u8],
    authenticated_data: &[u8],
) -> Result<Vec<u8>, AesGcmError> {
    let key = SymmetricKey::try_from_bytes(key)?;
    let mut rng = CsRng::from_entropy();

    let nonce = Nonce::new(&mut rng);
    let mut result = Vec::with_capacity(plaintext.len() + ENCRYPTION_OVERHEAD);
    result.extend(nonce.as_bytes());
    result.extend(Aes256GcmRust::new(&key).encrypt(&nonce, plaintext, Some(authenticated_data))?);

    Ok(result)
}

pub fn decrypt(
    key: [u8; Aes256GcmRust::KEY_LENGTH],
    ciphertext: &[u8],
    authenticated_data: &[u8],
) -> Result<Vec<u8>, AesGcmError> {
    if ciphertext.len() <= ENCRYPTION_OVERHEAD {
        return Err(AesGcmError::CryptoCore(
            CryptoCoreError::CiphertextTooSmallError {
                ciphertext_len: ciphertext.len(),
                min: ENCRYPTION_OVERHEAD as u64,
            },
        ));
    }
    let key = SymmetricKey::try_from_bytes(key)?;
    let nonce = Nonce::try_from_slice(&ciphertext[..Aes256GcmRust::NONCE_LENGTH])?;
    let bytes = Aes256GcmRust::new(&key).decrypt(
        &nonce,
        &ciphertext[Aes256GcmRust::NONCE_LENGTH..],
        Some(authenticated_data),
    )?;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use cloudproof_cover_crypt::reexport::crypto_core::Aes256Gcm;

    use crate::core::aesgcm::{decrypt, encrypt};

    #[test]
    fn test_encrypt_decrypt() {
        let key = [42_u8; Aes256Gcm::KEY_LENGTH];
        let plaintext = b"plaintext";
        let authenticated_data = b"authenticated_data";
        let ciphertext = encrypt(key, plaintext, authenticated_data).unwrap();
        let cleartext = decrypt(key, &ciphertext, authenticated_data).unwrap();
        assert_eq!(plaintext.to_vec(), cleartext);
    }
}
