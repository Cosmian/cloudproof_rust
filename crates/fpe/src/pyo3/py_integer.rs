use num_bigint::BigUint;
use num_traits::Num;
use pyo3::{exceptions::PyException, prelude::*, types::PyString};

use crate::core::{Integer as IntegerRust, KEY_LENGTH};

#[pyclass]
pub struct Integer(IntegerRust);

#[pymethods]
impl Integer {
    #[new]
    fn new(radix: u32, digits: usize) -> PyResult<Self> {
        match IntegerRust::instantiate(radix, digits) {
            Ok(itg) => Ok(Self(itg)),
            Err(e) => Err(PyException::new_err(format!(
                "FPE Integer Instantiation failed: {e:?}"
            ))),
        }
    }

    fn encrypt_decrypt(
        &self,
        key: Vec<u8>,
        tweak: Vec<u8>,
        input: u64,
        encrypt_flag: bool,
    ) -> PyResult<u64> {
        if key.len() != KEY_LENGTH {
            return Err(PyException::new_err(format!(
                "FPE Integer error: key length incorrect: {}, expected {}",
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

    fn encrypt_decrypt_big(
        &self,
        key: Vec<u8>,
        tweak: Vec<u8>,
        input: String,
        encrypt_flag: bool,
        py: Python,
    ) -> PyResult<Py<PyString>> {
        if key.len() != KEY_LENGTH {
            return Err(PyException::new_err(format!(
                "FPE Integer error: key length incorrect: {}, expected {}",
                key.len(),
                KEY_LENGTH
            )));
        }
        let mut k: [u8; 32] = [0; 32];
        k.copy_from_slice(&key);

        let input_biguint = BigUint::from_str_radix(&input, self.0.radix).map_err(|e| {
            PyException::new_err(format!(
                "FPE Big Integer: conversion to BigUint failed: {e:?}"
            ))
        })?;

        let output = if encrypt_flag {
            self.0.encrypt_big(&k, &tweak, &input_biguint)
        } else {
            self.0.decrypt_big(&k, &tweak, &input_biguint)
        };
        match output {
            Ok(ciphertext) => Ok(PyString::new(py, &ciphertext.to_str_radix(self.0.radix)).into()),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    /// Encrypts a 64-bit plaintext value using the specified key and tweak.
    ///
    /// # Arguments
    ///
    /// * `key` - A vector of bytes representing the key used for encryption.
    /// * `tweak` - A vector of bytes representing the tweak used for
    ///   encryption.
    /// * `plaintext` - A 64-bit integer value representing the plaintext to
    ///   encrypt.
    ///
    /// # Returns
    ///
    /// A `PyResult` containing a 64-bit integer value representing the
    /// encrypted ciphertext. Returns an error if the encryption fails.
    pub fn encrypt(&self, key: Vec<u8>, tweak: Vec<u8>, plaintext: u64) -> PyResult<u64> {
        self.encrypt_decrypt(key, tweak, plaintext, true)
    }

    /// Decrypts a 64-bit ciphertext value using the specified key and tweak.
    ///
    /// # Arguments
    ///
    /// * `key` - A vector of bytes representing the key used for decryption.
    /// * `tweak` - A vector of bytes representing the tweak used for
    ///   decryption.
    /// * `ciphertext` - A 64-bit integer value representing the ciphertext to
    ///   decrypt.
    ///
    /// # Returns
    ///
    /// A `PyResult` containing a 64-bit integer value representing the
    /// decrypted plaintext. Returns an error if the decryption fails.
    pub fn decrypt(&self, key: Vec<u8>, tweak: Vec<u8>, ciphertext: u64) -> PyResult<u64> {
        self.encrypt_decrypt(key, tweak, ciphertext, false)
    }

    /// Encrypts the given plaintext using the specified key and tweak.
    ///
    /// # Arguments
    ///
    /// * `key` - A vector of bytes representing the key used for encryption.
    /// * `tweak` - A vector of bytes representing the tweak used for
    ///   encryption.
    /// * `plaintext` - A string containing the plaintext to encrypt.
    /// * `py` - A Python interpreter instance, used to return the encrypted
    ///   ciphertext as a PyString.
    ///
    /// # Returns
    ///
    /// A `PyResult` containing a `PyString` representing the encrypted
    /// ciphertext. Returns an error if the encryption fails.
    pub fn encrypt_big(
        &self,
        key: Vec<u8>,
        tweak: Vec<u8>,
        plaintext: String,
        py: Python,
    ) -> PyResult<Py<PyString>> {
        self.encrypt_decrypt_big(key, tweak, plaintext, true, py)
    }

    /// Decrypts the given ciphertext using the specified key and tweak.
    ///
    /// # Arguments
    ///
    /// * `key` - A vector of bytes representing the key used for decryption.
    /// * `tweak` - A vector of bytes representing the tweak used for
    ///   decryption.
    /// * `ciphertext` - A string containing the ciphertext to decrypt.
    /// * `py` - A Python interpreter instance, used to return the decrypted
    ///   plaintext as a PyString.
    ///
    /// # Returns
    ///
    /// A `PyResult` containing a `PyString` representing the decrypted
    /// plaintext. Returns an error if the decryption fails.
    pub fn decrypt_big(
        &self,
        key: Vec<u8>,
        tweak: Vec<u8>,
        ciphertext: String,
        py: Python,
    ) -> PyResult<Py<PyString>> {
        self.encrypt_decrypt_big(key, tweak, ciphertext, false, py)
    }
}
