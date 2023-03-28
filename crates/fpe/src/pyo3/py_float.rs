use pyo3::{exceptions::PyException, prelude::*};

use crate::core::{Float as FloatRust, KEY_LENGTH};

#[pyclass]
pub struct Float(FloatRust);

#[pymethods]
impl Float {
    #[new]
    fn new() -> PyResult<Self> {
        match FloatRust::instantiate() {
            Ok(itg) => Ok(Self(itg)),
            Err(e) => Err(PyException::new_err(format!(
                "FPE Float Instantiation failed: {e:?}"
            ))),
        }
    }

    fn encrypt_decrypt(
        &self,
        key: Vec<u8>,
        tweak: Vec<u8>,
        input: f64,
        encrypt_flag: bool,
    ) -> PyResult<f64> {
        if key.len() != KEY_LENGTH {
            return Err(PyException::new_err(format!(
                "FPE Float error: key length incorrect: {}, expected {}",
                key.len(),
                KEY_LENGTH
            )));
        }
        let mut k: [u8; 32] = [0; 32];
        k.copy_from_slice(&key);

        let output = if encrypt_flag {
            self.0.encrypt(&k, &tweak, input)
        } else {
            self.0.decrypt(&k, &tweak, input)
        };
        match output {
            Ok(ciphertext) => Ok(ciphertext),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    /// Encrypts a 64-bit floating point plaintext using FPE.
    ///
    /// # Arguments
    ///
    /// * `key`: A vector of bytes representing the encryption key.
    /// * `tweak`: A vector of bytes representing the encryption tweak.
    /// * `plaintext`: The plaintext to encrypt.
    ///
    /// # Returns
    ///
    /// The ciphertext resulting from encrypting the plaintext.
    ///
    /// # Errors
    ///
    /// Returns a Python error if there is an error during encryption.
    pub fn encrypt(&self, key: Vec<u8>, tweak: Vec<u8>, plaintext: f64) -> PyResult<f64> {
        self.encrypt_decrypt(key, tweak, plaintext, true)
    }

    /// Decrypts a 64-bit floating point ciphertext using FPE.
    ///
    /// # Arguments
    ///
    /// * `key`: A vector of bytes representing the encryption key.
    /// * `tweak`: A vector of bytes representing the encryption tweak.
    /// * `ciphertext`: The ciphertext to decrypt.
    ///
    /// # Returns
    ///
    /// The plaintext resulting from decrypting the ciphertext.
    ///
    /// # Errors
    ///
    /// Returns a Python error if there is an error during decryption.
    pub fn decrypt(&self, key: Vec<u8>, tweak: Vec<u8>, ciphertext: f64) -> PyResult<f64> {
        self.encrypt_decrypt(key, tweak, ciphertext, false)
    }
}
