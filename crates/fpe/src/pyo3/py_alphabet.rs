use pyo3::{exceptions::PyException, prelude::*, types::PyString};

use crate::{core::Alphabet as AlphabetRust, get_alphabet};

#[pyclass]
pub struct Alphabet(AlphabetRust);

#[pymethods]
impl Alphabet {
    /// Creates a new instance of AlphabetRust based on the provided
    /// alphabet_type string.
    ///
    /// # Arguments
    ///
    /// * alphabet_type - A string slice that represents the type of the
    ///   alphabet to create. Must be one of the following:
    ///
    /// * "numeric" - Numeric alphabet
    /// * "hexa_decimal" - Hexadecimal alphabet
    /// * "alpha_lower" - Lowercase alphabet
    /// * "alpha_upper" - Uppercase alphabet
    /// * "alpha" - Alphabetic alphabet
    /// * "alpha_numeric" - Alphanumeric alphabet
    /// * "utf" - UTF-8 alphabet
    /// * "chinese" - Chinese alphabet
    /// * "latin1sup" - Latin1 supplement alphabet
    /// * "latin1sup_alphanum" - Latin1 supplement alphanumeric alphabet
    ///
    /// # Errors
    ///
    /// This function will return an error if the alphabet_type is unknown or
    /// unsupported.
    #[new]
    fn new(alphabet_id: &str) -> PyResult<Self> {
        Ok(Self(get_alphabet(alphabet_id).map_err(|e| {
            PyException::new_err(format!("Instantiation failed, unknown type: {e:?}"))
        })?))
    }

    /// Encrypts a given plaintext using the specified key and tweak using the
    /// underlying encryption algorithm of the block cipher mode of
    /// operation.
    ///
    /// # Arguments
    ///
    /// * `self` - The reference to the object on which this method is called.
    /// * `key` - The key bytes used for encryption.
    /// * `tweak` - The tweak bytes used for encryption.
    /// * `plaintext` - The plaintext to encrypt.
    /// * `py` - The Python interpreter to use for creating the PyString object.
    ///
    /// # Returns
    ///
    /// Returns a PyResult of Py<PyString> object representing the encrypted
    /// ciphertext if the encryption was successful. Otherwise, returns a
    /// PyException error.
    pub fn encrypt(
        &self,
        key: Vec<u8>,
        tweak: Vec<u8>,
        plaintext: String,
        py: Python,
    ) -> PyResult<Py<PyString>> {
        match self.0.encrypt(&key, &tweak, &plaintext) {
            Ok(ciphertext) => Ok(PyString::new(py, &ciphertext).into()),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    /// Decrypts the given `ciphertext` using the specified `key` and `tweak`.
    ///
    /// # Arguments
    ///
    /// * `&self` - The reference to the object on which this method is called.
    /// * `key` - a `Vec<u8>` containing the encryption key.
    /// * `tweak` - a `Vec<u8>` containing the tweak value.
    /// * `ciphertext` - a `String` containing the ciphertext to decrypt.
    /// * `py` - a `Python` instance used to create the `PyString` return value.
    ///
    /// # Returns
    ///
    /// Returns a `PyResult` containing either a `PyString` with the decrypted
    /// cleartext or a `PyException` if an error occurred during decryption.
    pub fn decrypt(
        &self,
        key: Vec<u8>,
        tweak: Vec<u8>,
        ciphertext: String,
        py: Python,
    ) -> PyResult<Py<PyString>> {
        match self.0.decrypt(&key, &tweak, &ciphertext) {
            Ok(cleartext) => Ok(PyString::new(py, &cleartext).into()),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    /// Extends the given object with additional characters.
    ///
    /// # Arguments
    ///
    /// * `&mut self` - The reference to the object on which this method is
    ///   called.
    /// * `additional_characters` - a `String` containing the additional
    ///   characters to add.
    pub fn extend_with(&mut self, additional_characters: String) {
        self.0.extend_with(&additional_characters);
    }
}
