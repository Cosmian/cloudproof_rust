use std::{collections::HashMap, fmt::Display, str::FromStr};

use base64::{engine::general_purpose::STANDARD, Engine};
use cosmian_crypto_core::{kdf256, FixedSizeCBytes, SymmetricKey};
use cosmian_findex::{UserKey as FindexUserKey, USER_KEY_LENGTH as FINDEX_USER_KEY_LENGTH};

use super::CallbackPrefix;
use crate::db_interfaces::DbInterfaceError;

/// Seed used to generate KMAC keys.
pub const SIGNATURE_SEED_LENGTH: usize = 16;

/// A token is a string containing all private information required to perform
/// authenticated requests to a Findex backend.
///
/// The string is encoded as follow:
/// 1. `index_id` `INDEX_ID_LENGTH` chars (see `Token@index_id`)
/// 2. `base64` representation of the Findex master key
/// 2. `base64` representation of the signature seeds, each one serialized as:
///     1. 1 byte prefix identifying the associated callback
///     2. `SIGNATURE_SEED_LENGTH` bytes of callback signature key
///
/// Currently each callback has a different associated signature key.
///
/// TODO: Only one key for each callback could be used, if it does not leak if a
/// given `fetch` is performed during an upsert or a search while still giving
/// fine grain control over permissions.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizationToken {
    pub(crate) index_id: String,
    pub(crate) findex_key: FindexUserKey,
    seeds: HashMap<CallbackPrefix, SymmetricKey<SIGNATURE_SEED_LENGTH>>,
}

impl Clone for AuthorizationToken {
    fn clone(&self) -> Self {
        let new_findex_key = SymmetricKey::try_from_slice(&self.findex_key).unwrap();
        let new_seeds = self
            .seeds
            .iter()
            .map(|(callback, key)| (*callback, SymmetricKey::try_from_slice(key).unwrap()))
            .collect();
        Self {
            index_id: self.index_id.clone(),
            findex_key: new_findex_key,
            seeds: new_seeds,
        }
    }
}

pub const INDEX_ID_LENGTH: usize = 5;

impl Display for AuthorizationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut seeds = Vec::with_capacity(
            FINDEX_USER_KEY_LENGTH + self.seeds.len() * (1 + SIGNATURE_SEED_LENGTH),
        );
        seeds.extend(self.findex_key.as_ref());
        for (callback, seed) in &self.seeds {
            seeds.push(*callback as u8);
            seeds.extend(seed.as_ref());
        }
        write!(f, "{}{}", self.index_id, STANDARD.encode(seeds))
    }
}

impl FromStr for AuthorizationToken {
    type Err = DbInterfaceError;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        let (index_id, tail) = token.split_at(INDEX_ID_LENGTH);
        let bytes = STANDARD.decode(tail).map_err(|e| {
            Self::Err::MalformedToken(format!("the keys section is not base64 encoded ({e})"))
        })?;

        if bytes.len() < FINDEX_USER_KEY_LENGTH {
            return Err(Self::Err::MalformedToken(
                "cannot read the Findex master key at the beginning of the keys section: token \
                 too small"
                    .to_string(),
            ));
        }
        let mut pos = 0;

        let findex_key = SymmetricKey::try_from_slice(&bytes[..FINDEX_USER_KEY_LENGTH])?;
        pos += FINDEX_USER_KEY_LENGTH;

        let mut token = Self {
            index_id: index_id.to_owned(),
            findex_key,
            seeds: Default::default(),
        };

        while SIGNATURE_SEED_LENGTH < bytes.len() - pos {
            let prefix = bytes[pos];
            let callback = <CallbackPrefix>::try_from(prefix).map_err(|e| {
                Self::Err::MalformedToken(format!(
                    "unknown prefix {prefix} at keys section offset {pos}: {e}",
                ))
            })?;
            pos += 1;

            let key = SymmetricKey::try_from_slice(&bytes[pos..pos + SIGNATURE_SEED_LENGTH])?;
            pos += SIGNATURE_SEED_LENGTH;

            token.seeds.insert(callback, key);
        }

        if pos != bytes.len() {
            Err(Self::Err::MalformedToken(format!(
                "{} bytes remaining from which a callback seed cannot be read (should be at \
                 leasts {} bytes)",
                bytes.len() - pos,
                1 + SIGNATURE_SEED_LENGTH
            )))
        } else {
            Ok(token)
        }
    }
}

impl AuthorizationToken {
    pub fn new(
        index_id: String,
        findex_key: SymmetricKey<FINDEX_USER_KEY_LENGTH>,
        seeds: HashMap<CallbackPrefix, SymmetricKey<SIGNATURE_SEED_LENGTH>>,
    ) -> Result<Self, DbInterfaceError> {
        if index_id.len() != INDEX_ID_LENGTH {
            Err(DbInterfaceError::MalformedToken(format!(
                "wrong index ID length: got {}, needed {} ({})",
                index_id.len(),
                INDEX_ID_LENGTH,
                index_id
            )))
        } else {
            Ok(Self {
                index_id,
                findex_key,
                seeds,
            })
        }
    }

    pub fn reduce_permissions(&mut self, read: bool, write: bool) -> Result<(), DbInterfaceError> {
        match (read, write) {
            (true, true) => {}
            (true, false) => {
                self.seeds.remove(&CallbackPrefix::Insert);
                self.seeds.remove(&CallbackPrefix::DeleteEntry);
                self.seeds.remove(&CallbackPrefix::DeleteChain);
                self.seeds.remove(&CallbackPrefix::Upsert);
            }
            (false, true) => Err(DbInterfaceError::Other(
                "Write access needs read access.".to_string(),
            ))?,
            (false, false) => {
                self.seeds.clear();
            }
        }

        Ok(())
    }

    /// Derives the KMAC key for the given `callback` from the given `seed`.
    // TODO: change this to use 16 bytes key
    // TODO: use KDF128
    // TODO: create a type `Seed` and derive KMAC key from it adding the correct additional
    // information?
    #[must_use]
    pub fn get_key(&self, index_id: &str, callback: CallbackPrefix) -> Option<SymmetricKey<32>> {
        self.seeds.get(&callback).map(|seed| {
            let mut res = SymmetricKey::default();
            kdf256!(&mut res, seed, index_id.as_bytes(), b"KMAC key");
            res
        })
    }
}
