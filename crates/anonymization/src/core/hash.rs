use argon2::Argon2;
use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher as _, Sha3};

use crate::{ano_error, core::AnoError};

// Available hashing methods
#[derive(PartialEq, Eq)]
pub enum HashMethod {
    SHA2,
    SHA3,
    Argon2,
}

pub struct Hasher {
    method: HashMethod,    // The selected hash method
    salt: Option<Vec<u8>>, // An optional salt
}

impl Hasher {
    /// Creates a new `Hasher` instance using the specified hash method and an
    /// optional salt.
    ///
    /// # Arguments
    ///
    /// * `method` - The hash method to use. This can be one of the following:
    ///   * `SHA2` Fast and secure, but vulnerable to brute-force attacks.
    ///   * `SHA3` Secure and resistant to brute-force attacks, but slower than
    ///     SHA-256 and not as widely supported.
    ///   * `Argon2` Highly resistant to brute-force attacks, but can be slower
    ///     than other hash functions and may require more memory.
    /// * `salt` - An optional salt to use. Required with Argon2
    pub fn new(method: HashMethod, salt: Option<Vec<u8>>) -> Result<Self, AnoError> {
        if method == HashMethod::Argon2 && salt.is_none() {
            return Err(ano_error!("Argon2 requires a salt value."));
        }
        Ok(Self { method, salt })
    }

    /// Applies the chosen hash method to the input data
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice representing the input data to be hashed.
    ///
    /// # Returns
    ///
    /// The base64-encoded hash string.
    pub fn apply(&self, data: &[u8]) -> Result<String, AnoError> {
        match self.method {
            HashMethod::SHA2 => {
                let mut hasher = Sha256::new();

                if let Some(salt_val) = self.salt.as_deref() {
                    hasher.update(salt_val);
                }
                hasher.update(data);

                Ok(general_purpose::STANDARD.encode(hasher.finalize()))
            }
            HashMethod::SHA3 => {
                let mut hasher = Sha3::v256();

                let mut output = [0u8; 32];
                if let Some(salt_val) = self.salt.as_deref() {
                    hasher.update(salt_val);
                }
                hasher.update(data);
                hasher.finalize(&mut output);

                Ok(general_purpose::STANDARD.encode(output))
            }
            HashMethod::Argon2 => {
                let salt_val = self
                    .salt
                    .as_deref()
                    .ok_or(ano_error!("Argon2 requires a salt value."))?;

                let mut output = [0u8; 32];
                Argon2::default().hash_password_into(data, salt_val, &mut output)?;

                Ok(general_purpose::STANDARD.encode(output))
            }
        }
    }
}
