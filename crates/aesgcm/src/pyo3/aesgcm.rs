use pyo3::{exceptions::PyException, pyclass, pymethods, PyResult};

use crate::core::{ReExposedAesGcm, KEY_LENGTH, NONCE_LENGTH};

#[pyclass]
pub struct AesGcm(ReExposedAesGcm);

#[pymethods]
impl AesGcm {
    #[new]
    fn new(key: Vec<u8>, nonce: Vec<u8>) -> PyResult<Self> {
        // Copy the key bytes into a 32-byte array
        let k: [u8; KEY_LENGTH] = key.try_into().map_err(|_e| {
            PyException::new_err(format!(
                "AESGCM error: key length incorrect: expected {KEY_LENGTH}"
            ))
        })?;
        // Copy the nonce bytes into a 12-byte array
        let n: [u8; NONCE_LENGTH] = nonce.try_into().map_err(|_e| {
            PyException::new_err(format!(
                "AESGCM error: nonce length incorrect: expected {NONCE_LENGTH}"
            ))
        })?;

        let aesgcm = ReExposedAesGcm::instantiate(&k, &n).map_err(|e| {
            PyException::new_err(format!("AESGCM error: cipher instantiation failed: {e}"))
        })?;
        Ok(Self(aesgcm))
    }

    fn encrypt(&self, plaintext: Vec<u8>) -> PyResult<Vec<u8>> {
        Ok(self.0.encrypt(&plaintext)?)
    }

    fn decrypt(&self, ciphertext: Vec<u8>) -> PyResult<Vec<u8>> {
        Ok(self.0.decrypt(&ciphertext)?)
    }
}
