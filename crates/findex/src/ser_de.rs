use std::{collections::HashSet, fmt::Display, hash::Hash, num::TryFromIntError};

use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    CryptoCoreError,
};
use cosmian_findex::{parameters::UID_LENGTH, CoreError as FindexCoreError, Uid};

#[derive(Debug)]
pub enum SerializableSetError {
    Serialization(String),
    Conversion(TryFromIntError),
}

impl Display for SerializableSetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialization(error) => write!(f, "{error}"),
            Self::Conversion(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SerializableSetError {}

impl From<CryptoCoreError> for SerializableSetError {
    fn from(value: CryptoCoreError) -> Self {
        Self::Serialization(value.to_string())
    }
}

impl From<FindexCoreError> for SerializableSetError {
    fn from(value: FindexCoreError) -> Self {
        Self::Serialization(value.to_string())
    }
}

impl From<TryFromIntError> for SerializableSetError {
    fn from(value: TryFromIntError) -> Self {
        Self::Conversion(value)
    }
}

pub fn serialize_set<SerializationError, T>(
    set: &HashSet<T>,
) -> Result<Vec<u8>, SerializableSetError>
where
    T: Serializable<Error = SerializationError> + Hash,
    SerializableSetError: From<SerializationError>,
{
    let mut ser = Serializer::with_capacity(set.len());
    ser.write_leb128_u64(set.len() as u64)?;
    for element in set {
        ser.write(element)?;
    }
    Ok(ser.finalize())
}

pub fn deserialize_set<SerializationError, T>(
    bytes: &[u8],
) -> Result<HashSet<T>, SerializableSetError>
where
    T: Serializable<Error = SerializationError> + Eq + Hash,
    SerializableSetError: From<SerializationError>,
{
    let mut de = Deserializer::new(bytes);
    let length = usize::try_from(de.read_leb128_u64()?)?;
    let mut set = HashSet::with_capacity(length);
    for _ in 0..length {
        set.insert(de.read::<T>()?);
    }
    if de.value().is_empty() {
        Ok(set)
    } else {
        Err(SerializableSetError::Serialization(
            "Remaining bytes after set deserialization".to_string(),
        ))
    }
}

pub fn serialize_fetch_entry_table_results(
    fetch_entry_table_results: Vec<(Uid<UID_LENGTH>, Vec<u8>)>,
) -> Result<Vec<u8>, SerializableSetError> {
    let mut se = Serializer::new();
    se.write_leb128_u64(fetch_entry_table_results.len() as u64)?;
    for (uid, value) in fetch_entry_table_results {
        se.write_array(&uid)?;
        se.write_vec(&value)?;
    }
    Ok(se.finalize())
}

pub fn deserialize_fetch_entry_table_results(
    bytes: &[u8],
) -> Result<Vec<(Uid<UID_LENGTH>, Vec<u8>)>, SerializableSetError> {
    let mut de = Deserializer::new(bytes);
    let length = <usize>::try_from(de.read_leb128_u64()?)?;
    let mut items = Vec::with_capacity(length);
    for _ in 0..length {
        let key = Uid::from(de.read_array()?);
        let value = de.read_vec()?;
        items.push((key, value));
    }
    Ok(items)
}
