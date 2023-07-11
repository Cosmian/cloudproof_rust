use cloudproof_cover_crypt::reexport::crypto_core::{
    Aes256Gcm as Aes256GcmRust, CryptoCoreError, Dem, FixedSizeCBytes, Instantiable, Nonce,
    SymmetricKey,
};

use crate::error::AesGcmError;

pub const BLOCK_LENGTH: usize = 16;

/// The `encrypt` function takes a key, nonce, plaintext, and authenticated data
/// as input and returns the encrypted ciphertext using AES-256 GCM encryption
/// in Rust.
///
/// Arguments:
///
/// * `key`: The `key` parameter is a 32-byte array representing the encryption
///   key
/// used in the AES-256-GCM encryption algorithm.
/// * `nonce`: The `nonce` parameter is a unique value used as an input to the
/// encryption algorithm. It is typically a random value that should never be
/// reused with the same key. The length of the `nonce` is determined by the
/// `Aes256GcmRust::NONCE_LENGTH` constant,
/// * `plaintext`: The `plaintext` parameter is the data that you want to
///   encrypt.
/// It is a slice of bytes (`&[u8]`) that represents the raw data that you want
/// to protect.
/// * `authenticated_data`: The `authenticated_data` parameter is additional
///   data
/// that is authenticated but not encrypted. It is used to provide integrity and
/// authenticity to the encrypted data. This data is included in the
/// authentication tag calculation but is not included in the encrypted output.
///
/// Returns:
///
/// a `Result` type, specifically `Result<Vec<u8>, AesGcmError>`. This means
/// that the function can either return an `Ok` variant containing a `Vec<u8>`
/// (the encrypted data) or an `Err` variant containing an `AesGcmError` (an
/// error occurred during encryption).
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

/// The `decrypt` function takes a key, nonce, ciphertext, and authenticated
/// data as input and returns the decrypted bytes if successful, or an error if
/// the ciphertext is too small or if there is an issue with the cryptographic
/// core.
///
/// Arguments:
///
/// * `key`: The `key` parameter is an array of 32 bytes representing the
///   encryption
/// key used for decryption. It is of type `[u8; Aes256GcmRust::KEY_LENGTH]`,
/// where `Aes256GcmRust::KEY_LENGTH` is the length of the key in
/// * `nonce`: The `nonce` parameter is a unique value used as an input to the
/// encryption algorithm. It is typically a random value that should never be
/// reused with the same key. The length of the `nonce` is determined by the
/// specific encryption algorithm being used. In this case, the `nonce` has
/// * `ciphertext`: The `ciphertext` parameter is a slice of bytes that
///   represents
/// the encrypted data. It contains the encrypted message that needs to be
/// decrypted.
/// * `authenticated_data`: The `authenticated_data` parameter is additional
///   data
/// that is authenticated but not encrypted. It is used to provide integrity and
/// authenticity to the encrypted message. This data is included in the
/// authentication tag calculation but is not included in the decrypted output.
/// It can be used to verify the integrity of the message and ensure
///
/// Returns:
///
/// a `Result` type. If the decryption is successful, it will return `Ok` with a
/// `Vec<u8>` containing the decrypted bytes. If there is an error during
/// decryption, it will return `Err` with an `AesGcmError` indicating the
/// specific error that occurred.
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
