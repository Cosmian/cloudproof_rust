use aes_gcm::{
    aead::{consts::U12, generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use crate::error::AesGcmError;

pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 12;
#[allow(dead_code)]
pub const BLOCK_LENGTH: usize = 16;

#[allow(dead_code)]
/// The `ReExposedAesGcm` struct contains an instance of the `Aes256Gcm` cipher
/// and a nonce of length 12. The crate `aesgcm` has received one security audit
/// by NCC Group, with no significant findings. We would like to thank
/// `MobileCoin` for funding the audit.
///
/// Properties:
///
/// * `cipher`: `cipher` is a property of type `Aes256Gcm`, which is a struct
/// representing the AES-GCM cipher with a 256-bit key size. It is used for
/// encrypting and decrypting data using the AES-GCM algorithm.
/// * `nonce`: The `nonce` property is a 12-byte array used as a unique value
///   for
/// each encryption operation in the AES-GCM encryption mode. It is important
/// that the nonce is never reused with the same key, as this can compromise the
/// security of the encryption.
pub struct ReExposedAesGcm {
    cipher: Aes256Gcm,
    nonce: GenericArray<u8, U12>,
}

impl ReExposedAesGcm {
    #[allow(dead_code)]
    /// This function instantiates an AES-256-GCM cipher object with a given key
    /// and nonce.
    ///
    /// Arguments:
    ///
    /// * `key`: The `key` parameter is a reference to a byte array of length
    ///   32, which
    /// is used to create an instance of the `Aes256Gcm` cipher object. This key
    /// is used to encrypt and decrypt data using the cipher.
    /// * `nonce`: The `nonce` parameter is a 12-byte array representing a
    ///   unique value
    /// used in the encryption process to ensure that each message encrypted
    /// with the same key is unique. It stands for "number used once".
    ///
    /// Returns:
    ///
    /// a `Result` object that contains either an instance of the struct `Self`
    /// or a `CloudproofError` if an error occurs during the execution of
    /// the function.
    pub fn instantiate(
        key: &[u8; KEY_LENGTH],
        nonce: &[u8; NONCE_LENGTH],
    ) -> Result<Self, AesGcmError> {
        // Create the cipher object
        let cipher = Aes256Gcm::new_from_slice(key)?;

        // Transformed from a byte array:
        let nonce = *Nonce::from_slice(nonce);

        Ok(Self { cipher, nonce })
    }

    #[allow(dead_code)]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AesGcmError> {
        Ok(self.cipher.encrypt(&self.nonce, plaintext)?)
    }

    #[allow(dead_code)]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, AesGcmError> {
        Ok(self.cipher.decrypt(&self.nonce, ciphertext)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::core::{aesgcm::ReExposedAesGcm, KEY_LENGTH, NONCE_LENGTH};

    #[test]
    fn test_encrypt_decrypt() {
        let key = [42_u8; KEY_LENGTH];
        let nonce = [42_u8; NONCE_LENGTH];
        let plaintext = b"plaintext";
        let aesgcm = ReExposedAesGcm::instantiate(&key, &nonce).unwrap();
        let ciphertext = aesgcm.encrypt(plaintext).unwrap();
        let cleartext = aesgcm.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.to_vec(), cleartext);
    }
}
