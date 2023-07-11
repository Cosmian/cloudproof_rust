use cloudproof_cover_crypt::reexport::crypto_core::{
    Aes256Gcm as Aes256GcmRust, CryptoCoreError, Dem, FixedSizeCBytes, Instantiable, Nonce,
    SymmetricKey,
};

use crate::error::AesGcmError;

pub const BLOCK_LENGTH: usize = 16;

pub fn encrypt(
    key: [u8; Aes256GcmRust::KEY_LENGTH],
    nonce: [u8; Aes256GcmRust::NONCE_LENGTH],
    plaintext: &[u8],
    authenticated_data: &[u8],
) -> Result<Vec<u8>, AesGcmError> {
    let key = SymmetricKey::try_from_bytes(key)?;
    let nonce = Nonce::try_from_bytes(nonce)?;
    Ok(Aes256GcmRust::new(&key).encrypt(&nonce, plaintext, Some(authenticated_data))?)
}

pub fn decrypt(
    key: [u8; Aes256GcmRust::KEY_LENGTH],
    nonce: [u8; Aes256GcmRust::NONCE_LENGTH],
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
    let key = SymmetricKey::try_from_bytes(key)?;
    let nonce = Nonce::try_from_bytes(nonce)?;
    let bytes = Aes256GcmRust::new(&key).decrypt(&nonce, ciphertext, Some(authenticated_data))?;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use cloudproof_cover_crypt::reexport::crypto_core::Aes256Gcm;

    use crate::core::aesgcm::{decrypt, encrypt};

    #[test]
    fn test_encrypt_decrypt() {
        let key = [42_u8; Aes256Gcm::KEY_LENGTH];
        let nonce = [42_u8; Aes256Gcm::NONCE_LENGTH];
        let plaintext = b"plaintext";
        let authenticated_data = b"authenticated_data";
        let ciphertext = encrypt(key, nonce, plaintext, authenticated_data).unwrap();
        let cleartext = decrypt(key, nonce, &ciphertext, authenticated_data).unwrap();
        assert_eq!(plaintext.to_vec(), cleartext);
    }
}
