use pyo3::{pyclass, pymethods, PyResult};

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
        Ok(encrypt(&key, &nonce, &plaintext, &authenticated_data)?)
    }

    #[staticmethod]
    fn decrypt(
        key: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        authenticated_data: Vec<u8>,
    ) -> PyResult<Vec<u8>> {
        Ok(decrypt(&key, &nonce, &ciphertext, &authenticated_data)?)
    }
}
