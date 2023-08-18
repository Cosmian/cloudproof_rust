use std::{collections::HashMap, fmt::Display, str::FromStr};

use base64::{engine::general_purpose::STANDARD, Engine};
use cosmian_crypto_core::{
    bytes_ser_de::{to_leb128_len, Serializable},
    kdf128, FixedSizeCBytes, SymmetricKey,
};
use cosmian_findex::{UserKey as FindexUserKey, USER_KEY_LENGTH as FINDEX_USER_KEY_LENGTH};

use crate::backends::{BackendError, CallbackPrefix};

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
pub struct FindexToken {
    pub(crate) index_id: u32,
    findex_key: FindexUserKey,
    seeds: HashMap<CallbackPrefix, SymmetricKey<SIGNATURE_SEED_LENGTH>>,
}

impl Serializable for FindexToken {
    type Error = BackendError;

    fn length(&self) -> usize {
        to_leb128_len(self.index_id as usize)
            + FINDEX_USER_KEY_LENGTH
            + to_leb128_len(self.seeds.len())
            + (1 + SIGNATURE_SEED_LENGTH) * self.seeds.len()
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.index_id as u64)?;
        n += ser.write_array(&self.findex_key)?;

        n += ser.write_leb128_u64(self.seeds.len() as u64)?;
        for (callback, seed) in &self.seeds {
            n += ser.write_leb128_u64((*callback as u8) as u64)?;
            n += ser.write_array(seed.as_ref())?;
        }

        Ok(n)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let index_id = <u32>::try_from(de.read_leb128_u64()?)?;
        let findex_master_key =
            SymmetricKey::<FINDEX_USER_KEY_LENGTH>::try_from_bytes(de.read_array()?)?;

        let n = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut seeds = HashMap::with_capacity(n);
        for _ in 0..n {
            let callback = <u8>::try_from(de.read_leb128_u64()?)?;
            let seed = SymmetricKey::<SIGNATURE_SEED_LENGTH>::try_from_bytes(de.read_array()?)?;
            seeds.insert(CallbackPrefix::try_from(callback)?, seed);
        }

        Ok(Self {
            index_id,
            findex_key: findex_master_key,
            seeds,
        })
    }
}

impl Display for FindexToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let serialized_token = self.serialize().map_err(|_| std::fmt::Error)?;
        write!(f, "{}", STANDARD.encode(&serialized_token))
    }
}

impl FromStr for FindexToken {
    type Err = BackendError;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        let bytes = STANDARD.decode(token).map_err(|e| {
            BackendError::MalformedToken(format!("token is not a valid base64 encoding: {e}"))
        })?;

        Self::deserialize(&bytes)
            .map_err(|e| Self::Err::Serialization(format!("token cannot be deserialized: {e:?}")))
    }
}

impl FindexToken {
    pub fn new(
        index_id: u32,
        findex_key: SymmetricKey<FINDEX_USER_KEY_LENGTH>,
        seeds: HashMap<CallbackPrefix, SymmetricKey<SIGNATURE_SEED_LENGTH>>,
    ) -> Self {
        Self {
            index_id,
            findex_key,
            seeds,
        }
    }

    pub fn reduce_permissions(&mut self, read: bool, write: bool) -> Result<(), BackendError> {
        match (read, write) {
            (true, true) => {}
            (true, false) => {
                self.seeds.remove(&CallbackPrefix::Insert);
                self.seeds.remove(&CallbackPrefix::Delete);
                self.seeds.remove(&CallbackPrefix::Upsert);
            }
            (false, true) => Err(BackendError::Other(
                "Write access needs read access.".to_string(),
            ))?,
            (false, false) => {
                self.seeds.drain();
            }
        }

        Ok(())
    }

    /// Derives the KMAC key for the given `callback` from the given `seed`.
    pub fn get_key(
        &self,
        callback: CallbackPrefix,
    ) -> Option<SymmetricKey<FINDEX_USER_KEY_LENGTH>> {
        self.seeds.get(&callback).map(|seed| {
            let mut res = SymmetricKey::default();
            kdf128!(&mut res, seed);
            res
        })
    }
}
