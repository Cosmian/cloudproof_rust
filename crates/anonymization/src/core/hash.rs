use argon2::Argon2;
use base64::{engine::general_purpose, Engine as _};
use tiny_keccak::{Hasher as _, Sha3};

use crate::{ano_error, core::AnoError};

pub enum HashMethod {
    SHA2,
    SHA3,
    Argon2,
}

pub struct Hasher {
    pub method: HashMethod,
    pub salt: Option<Vec<u8>>,
}

impl Hasher {
    pub fn apply(&self, data: &[u8]) -> Result<String, AnoError> {
        match self.method {
            HashMethod::SHA2 => match &self.salt {
                Some(salt_val) => {
                    let mut salted_data = salt_val.clone();
                    salted_data.extend(data);
                    Ok(sha256::digest(salted_data.as_slice()))
                }
                None => Ok(sha256::digest(data)),
            },
            HashMethod::SHA3 => {
                let mut hasher = Sha3::v256();
                let mut output = [0u8; 32];
                hasher.update(data);
                if let Some(salt_val) = &self.salt {
                    hasher.update(salt_val);
                }

                hasher.finalize(&mut output);

                Ok(general_purpose::STANDARD.encode(output))
            }
            HashMethod::Argon2 => {
                let salt_val = self
                    .salt
                    .as_deref()
                    .ok_or(ano_error!("Argon2 requires Salt"))?;

                let mut output = [0u8; 32]; // Can be any desired size
                Argon2::default().hash_password_into(data, salt_val, &mut output)?;

                Ok(general_purpose::STANDARD.encode(output))
            }
        }
    }
}
