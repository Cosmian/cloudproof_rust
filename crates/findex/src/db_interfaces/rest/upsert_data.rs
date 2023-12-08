use std::{
    collections::HashMap,
    fmt::Display,
    ops::{Deref, DerefMut},
};

use cosmian_crypto_core::bytes_ser_de::{to_leb128_len, Deserializer, Serializable, Serializer};
use cosmian_findex::{EncryptedValue, Token, TokenToEncryptedValueMap};

use crate::db_interfaces::DbInterfaceError;

#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct UpsertData<const VALUE_LENGTH: usize>(
    HashMap<
        Token,
        (
            Option<EncryptedValue<VALUE_LENGTH>>,
            EncryptedValue<VALUE_LENGTH>,
        ),
    >,
);

impl<const VALUE_LENGTH: usize> Display for UpsertData<VALUE_LENGTH> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Modifications: {{")?;
        for (token, (old_value, new_value)) in self.iter() {
            writeln!(
                f,
                "  '{token}': '{}' -> '{new_value}'",
                old_value
                    .as_ref()
                    .map(std::string::ToString::to_string)
                    .unwrap_or_default()
            )?;
        }
        writeln!(f, "}}")
    }
}

impl<const VALUE_LENGTH: usize> UpsertData<VALUE_LENGTH> {
    /// Build the upsert data from the old and new tables.
    ///
    /// - `old_table`   : previous state of the table
    /// - `new_table`   : new state of the table
    pub fn new(
        mut old_table: TokenToEncryptedValueMap<VALUE_LENGTH>,
        new_table: TokenToEncryptedValueMap<VALUE_LENGTH>,
    ) -> Self {
        Self(
            new_table
                .into_iter()
                .map(|(token, new_value)| {
                    let old_value = old_table.remove(&token);
                    (token, (old_value, new_value))
                })
                .collect(),
        )
    }
}

impl<const VALUE_LENGTH: usize> Deref for UpsertData<VALUE_LENGTH> {
    type Target = HashMap<
        Token,
        (
            Option<EncryptedValue<VALUE_LENGTH>>,
            EncryptedValue<VALUE_LENGTH>,
        ),
    >;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const VALUE_LENGTH: usize> DerefMut for UpsertData<VALUE_LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const VALUE_LENGTH: usize> IntoIterator for UpsertData<VALUE_LENGTH> {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = (
        Token,
        (
            Option<EncryptedValue<VALUE_LENGTH>>,
            EncryptedValue<VALUE_LENGTH>,
        ),
    );

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<const VALUE_LENGTH: usize> Serializable for UpsertData<VALUE_LENGTH> {
    type Error = DbInterfaceError;

    fn length(&self) -> usize {
        self.values()
            .map(|(old_value, _)| {
                let old_value_len = old_value
                    .as_ref()
                    .map(|_| EncryptedValue::<VALUE_LENGTH>::LENGTH)
                    .unwrap_or_default();
                Token::LENGTH
                    + to_leb128_len(old_value_len)
                    + old_value_len
                    + to_leb128_len(EncryptedValue::<VALUE_LENGTH>::LENGTH)
                    + EncryptedValue::<VALUE_LENGTH>::LENGTH
            })
            .sum()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.len() as u64)?;
        for (token, (old_value, new_value)) in self.iter() {
            n += ser.write_array(token)?;
            n += ser.write_vec(
                old_value
                    .as_ref()
                    .map(<Vec<u8>>::from)
                    .unwrap_or_default()
                    .as_slice(),
            )?;
            n += ser.write_vec(&<Vec<u8>>::from(new_value))?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let length = de.read_leb128_u64()? as usize;
        let mut res = HashMap::with_capacity(length);
        for _ in 0..length {
            let token = de.read_array::<{ Token::LENGTH }>()?;
            let old_value = de.read_vec()?;
            let old_value = if old_value.is_empty() {
                None
            } else {
                Some(EncryptedValue::try_from(old_value.as_slice())?)
            };
            let new_value = EncryptedValue::try_from(de.read_vec()?.as_slice())?;
            res.insert(token.into(), (old_value, new_value));
        }
        Ok(Self(res))
    }
}

#[cfg(test)]
mod tests {
    use cosmian_findex::ENTRY_LENGTH;

    use super::*;

    #[test]
    fn test_upsert_data_serialization() {
        let data = UpsertData::<ENTRY_LENGTH>(HashMap::from_iter([
            (
                Token::from([0; Token::LENGTH]),
                (
                    None,
                    EncryptedValue::try_from(
                        [1; EncryptedValue::<ENTRY_LENGTH>::LENGTH].as_slice(),
                    )
                    .unwrap(),
                ),
            ),
            (
                Token::from([1; Token::LENGTH]),
                (
                    Some(
                        EncryptedValue::try_from(
                            [2; EncryptedValue::<ENTRY_LENGTH>::LENGTH].as_slice(),
                        )
                        .unwrap(),
                    ),
                    EncryptedValue::try_from(
                        [3; EncryptedValue::<ENTRY_LENGTH>::LENGTH].as_slice(),
                    )
                    .unwrap(),
                ),
            ),
            (
                Token::from([2; Token::LENGTH]),
                (
                    None,
                    EncryptedValue::try_from(
                        [4; EncryptedValue::<ENTRY_LENGTH>::LENGTH].as_slice(),
                    )
                    .unwrap(),
                ),
            ),
        ]));
        let bytes = data.serialize().unwrap().to_vec();
        let res = UpsertData::<ENTRY_LENGTH>::deserialize(&bytes).unwrap();
        assert_eq!(data, res);
    }
}
