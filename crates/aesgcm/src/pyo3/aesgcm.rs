use cloudproof_cover_crypt::reexport::crypto_core::Aes256Gcm;
use pyo3::{exceptions::PyException, pyclass, pymethods, PyResult};

use crate::{decrypt, encrypt};

#[pyclass]
pub struct AesGcm;

#[pymethods]
impl AesGcm {
    #[staticmethod]
    fn encrypt(key: Vec<u8>, plaintext: Vec<u8>, authenticated_data: Vec<u8>) -> PyResult<Vec<u8>> {
        // Copy the key bytes into a 32-byte array
        let key: [u8; Aes256Gcm::KEY_LENGTH] = key.try_into().map_err(|_e| {
            PyException::new_err(format!(
                "AESGCM error: key length incorrect: expected {}",
                Aes256Gcm::KEY_LENGTH
            ))
        })?;
        Ok(encrypt(key, &plaintext, &authenticated_data)?)
    }

    #[staticmethod]
    fn decrypt(
        key: Vec<u8>,
        ciphertext: Vec<u8>,
        authenticated_data: Vec<u8>,
    ) -> PyResult<Vec<u8>> {
        // Copy the key bytes into a 32-byte array
        let key: [u8; Aes256Gcm::KEY_LENGTH] = key.try_into().map_err(|_e| {
            PyException::new_err(format!(
                "AESGCM error: key length incorrect: expected {}",
                Aes256Gcm::KEY_LENGTH
            ))
        })?;

        Ok(decrypt(key, &ciphertext, &authenticated_data)?)
    }
}
