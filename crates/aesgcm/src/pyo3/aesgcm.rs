use cloudproof_cover_crypt::reexport::crypto_core::Aes256Gcm as Aes256GcmRust;
use pyo3::{exceptions::PyException, pyclass, pymethods, PyResult};

use crate::{decrypt, encrypt};

#[pyclass]
pub struct Aes256Gcm;

#[pymethods]
impl Aes256Gcm {
    #[staticmethod]
    fn encrypt(
        key: Vec<u8>,
        nonce: Vec<u8>,
        plaintext: Vec<u8>,
        authenticated_data: Vec<u8>,
    ) -> PyResult<Vec<u8>> {
        // Copy the key bytes into a 32-byte array
        let key: [u8; Aes256GcmRust::KEY_LENGTH] = key.try_into().map_err(|_e| {
            PyException::new_err(format!(
                "AESGCM error: key length incorrect: expected {}",
                Aes256GcmRust::KEY_LENGTH
            ))
        })?;
        // Copy the nonce bytes into a 32-byte array
        let nonce: [u8; Aes256GcmRust::NONCE_LENGTH] = nonce.try_into().map_err(|_e| {
            PyException::new_err(format!(
                "AESGCM error: nonce length incorrect: expected {}",
                Aes256GcmRust::NONCE_LENGTH
            ))
        })?;
        Ok(encrypt(key, nonce, &plaintext, &authenticated_data)?)
    }

    #[staticmethod]
    fn decrypt(
        key: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        authenticated_data: Vec<u8>,
    ) -> PyResult<Vec<u8>> {
        // Copy the key bytes into a 32-byte array
        let key: [u8; Aes256GcmRust::KEY_LENGTH] = key.try_into().map_err(|_e| {
            PyException::new_err(format!(
                "AESGCM error: key length incorrect: expected {}",
                Aes256GcmRust::KEY_LENGTH
            ))
        })?;
        // Copy the nonce bytes into a 32-byte array
        let nonce: [u8; Aes256GcmRust::NONCE_LENGTH] = nonce.try_into().map_err(|_e| {
            PyException::new_err(format!(
                "AESGCM error: nonce length incorrect: expected {}",
                Aes256GcmRust::NONCE_LENGTH
            ))
        })?;

        Ok(decrypt(key, nonce, &ciphertext, &authenticated_data)?)
    }
}
