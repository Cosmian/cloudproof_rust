use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializer};
use cosmian_findex::{
    Data, EncryptedValue, IndexedValue, Keyword, Keywords, Token, TokenToEncryptedValueMap,
    TokenWithEncryptedValueList, Tokens,
};

use crate::ser_de::SerializationError;

/// Maximum number of bytes used by a LEB128 encoding.
///
/// `8` LEB128 bytes can encode numbers up to `2^56` which should be an upper
/// bound on the number of table lines
const MAX_LEB128_ENCODING_SIZE: usize = 8;

#[must_use]
pub const fn get_serialized_edx_lines_size_bound<const VALUE_LENGTH: usize>(
    n_lines: usize,
    n_tables: usize,
) -> usize {
    MAX_LEB128_ENCODING_SIZE
        + n_lines
            * n_tables
            * (Token::LENGTH + MAX_LEB128_ENCODING_SIZE + EncryptedValue::<VALUE_LENGTH>::LENGTH)
}

#[must_use]
pub fn get_upsert_output_size(
    modifications: &HashMap<IndexedValue<Keyword, Data>, Keywords>,
) -> usize {
    // Since `h_add` (resp. `h_delete`) returns the set of keywords that have been inserted (resp.
    // deleted), caller MUST know in advance how much memory is needed before calling `h_add`
    // (resp. `h_delete`).
    //
    // In order to centralize into Rust the computation of the allocation size, 2 calls to
    // `h_upsert` are required:
    //
    // - the first call is made with `results_len` with a 0 value. No indexation at all is done. It
    //   simply returns an upper bound estimation of the allocation needed store the results.
    // - the second call takes this returned value for `results_len`
    modifications
        .values()
        .flat_map(|set| set.iter().map(|e| MAX_LEB128_ENCODING_SIZE + e.len()))
        .sum::<usize>()
}
pub fn serialize_token_set(set: &Tokens) -> Result<Vec<u8>, SerializationError> {
    let mut ser = Serializer::with_capacity(set.len());
    ser.write_leb128_u64(set.len() as u64)?;
    for element in set.iter() {
        ser.write_array(element)?;
    }
    Ok(ser.finalize().to_vec())
}

pub fn deserialize_token_set(bytes: &[u8]) -> Result<Tokens, SerializationError> {
    let mut de = Deserializer::new(bytes);
    let length = usize::try_from(de.read_leb128_u64()?)?;
    let mut set = HashSet::with_capacity(length);
    for _ in 0..length {
        set.insert(Token::from(de.read_array()?));
    }
    if de.value().is_empty() {
        Ok(Tokens::from(set))
    } else {
        Err(SerializationError(
            "Remaining bytes after set deserialization".to_string(),
        ))
    }
}

pub fn serialize_keyword_set(set: &HashSet<Keyword>) -> Result<Vec<u8>, SerializationError> {
    let mut ser = Serializer::with_capacity(set.len());
    ser.write_leb128_u64(set.len() as u64)?;
    for element in set {
        ser.write_leb128_u64(element.len() as u64)?;
        ser.write_array(element)?;
    }
    let output = ser.finalize().to_vec();
    Ok(output)
} //TODO: merge functions

pub fn deserialize_keyword_set(keywords: &[u8]) -> Result<HashSet<Keyword>, SerializationError> {
    let mut de = Deserializer::new(keywords);
    let length = usize::try_from(de.read_leb128_u64()?)?;
    let mut set = HashSet::with_capacity(length);
    for _ in 0..length {
        set.insert(Keyword::from(de.read_vec()?));
    }
    if de.value().is_empty() {
        Ok(set)
    } else {
        Err(SerializationError(
            "Remaining bytes after set deserialization".to_string(),
        ))
    }
}

pub fn serialize_data_set(set: &HashSet<Data>) -> Result<Vec<u8>, SerializationError> {
    let mut ser = Serializer::with_capacity(set.len());
    ser.write_leb128_u64(set.len() as u64)?;
    for datum in set {
        ser.write_vec(datum)?;
    }
    Ok(ser.finalize().to_vec())
} //TODO: merge functions

pub fn deserialize_data_set(bytes: &[u8]) -> Result<HashSet<Data>, SerializationError> {
    let mut de = Deserializer::new(bytes);
    let length = <usize>::try_from(de.read_leb128_u64()?)?;
    let mut res = HashSet::with_capacity(length);
    for _ in 0..length {
        let datum = Data::from(de.read_vec()?);
        res.insert(datum);
    }
    Ok(res)
} //TODO: merge functions

pub fn serialize_edx_lines<const VALUE_LENGTH: usize>(
    map: &TokenToEncryptedValueMap<VALUE_LENGTH>,
) -> Result<Vec<u8>, SerializationError> {
    let mut ser = Serializer::with_capacity(map.len());
    ser.write_leb128_u64(map.len() as u64)?;
    for (uid, value) in map.iter() {
        ser.write_array(uid)?;
        ser.write_vec(&<Vec<u8>>::from(value))?;
    }
    Ok(ser.finalize().to_vec())
}

pub fn deserialize_edx_lines<const VALUE_LENGTH: usize>(
    bytes: &[u8],
) -> Result<TokenWithEncryptedValueList<VALUE_LENGTH>, SerializationError> {
    let mut de = Deserializer::new(bytes);
    let length = <usize>::try_from(de.read_leb128_u64()?)?;
    let mut items = Vec::with_capacity(length);
    for _ in 0..length {
        let key = Token::from(de.read_array()?);
        // TODO: since constant generics cannot be used as constant values, there is no way to use
        // `de.read_array<{ EncryptedValue::<VALUE_LENGTH>::LENGTH }>()` for now.
        let value = EncryptedValue::<VALUE_LENGTH>::try_from(de.read_vec()?.as_slice())?;
        items.push((key, value));
    }
    Ok(TokenWithEncryptedValueList::from(items))
}

pub fn serialize_indexed_values(
    map: &HashMap<IndexedValue<Keyword, Data>, HashSet<Keyword>>,
) -> Result<Vec<u8>, SerializationError> {
    let mut ser = Serializer::with_capacity(map.len());
    ser.write_leb128_u64(map.len() as u64)?;
    for (iv, keywords) in map {
        ser.write_vec(<Vec<u8>>::from(iv).as_slice())?;
        ser.write_leb128_u64(keywords.len() as u64)?;
        for element in keywords {
            ser.write_leb128_u64(element.len() as u64)?;
            ser.write_array(element)?;
        }
    }
    Ok(ser.finalize().to_vec())
}

pub fn deserialize_indexed_values(
    bytes: &[u8],
) -> Result<HashMap<IndexedValue<Keyword, Data>, HashSet<Keyword>>, SerializationError> {
    let mut de = Deserializer::new(bytes);
    let length = <usize>::try_from(de.read_leb128_u64()?)?;
    let mut items = HashMap::with_capacity(length);
    for _ in 0..length {
        let iv = IndexedValue::try_from(de.read_vec()?.as_slice())?;
        let keywords_number = usize::try_from(de.read_leb128_u64()?)?;
        let mut set = HashSet::with_capacity(keywords_number);
        for _ in 0..keywords_number {
            set.insert(Keyword::from(de.read_vec()?));
        }

        items.insert(iv, set);
    }
    Ok(items)
}

pub fn serialize_intermediate_results(
    res: &HashMap<Keyword, HashSet<IndexedValue<Keyword, Data>>>,
) -> Result<Vec<u8>, SerializationError> {
    let mut ser = Serializer::with_capacity(res.len());
    ser.write_leb128_u64(res.len() as u64)?;
    for (keyword, indexed_values) in res {
        ser.write_vec(keyword.as_ref())?;
        ser.write_leb128_u64(indexed_values.len() as u64)?;
        for iv in indexed_values {
            ser.write_vec(<Vec<u8>>::from(iv).as_slice())?;
        }
    }
    Ok(ser.finalize().to_vec())
}

#[cfg(test)]
mod tests {

    use cosmian_findex::{Token, Tokens};

    use super::*;

    #[test]
    fn test_uid_set_serialization() {
        let uids = Tokens::from_iter([
            Token::from([0; Token::LENGTH]),
            Token::from([1; Token::LENGTH]),
            Token::from([2; Token::LENGTH]),
            Token::from([3; Token::LENGTH]),
            Token::from([4; Token::LENGTH]),
            Token::from([5; Token::LENGTH]),
        ]);

        let serialized_uids = serialize_token_set(&uids).unwrap();
        let res = deserialize_token_set(&serialized_uids).unwrap();
        assert_eq!(uids, res);
    }

    #[test]
    fn test_indexed_values_serialization() {
        //
        // Index 1 keyword
        //
        let mut indexed_value_to_keywords = HashMap::new();
        let felix_location = Data::from(vec![0, 0, 0, 0, 0, 0, 0, 0]);
        indexed_value_to_keywords.insert(
            IndexedValue::<Keyword, Data>::Data(felix_location),
            HashSet::from_iter([Keyword::from("Felix")]),
        );
        let serialized_iv = serialize_indexed_values(&indexed_value_to_keywords).unwrap();
        let res = deserialize_indexed_values(&serialized_iv).unwrap();
        assert_eq!(indexed_value_to_keywords, res);

        //
        // Index 2 keywords
        //
        let mut indexed_value_to_keywords = HashMap::new();
        let robert_doe_location = Data::from("robert doe DB location");
        indexed_value_to_keywords.insert(
            IndexedValue::<Keyword, Data>::Data(robert_doe_location),
            HashSet::from_iter([Keyword::from("robert"), Keyword::from("doe")]),
        );
        let serialized_iv = serialize_indexed_values(&indexed_value_to_keywords).unwrap();
        let res = deserialize_indexed_values(&serialized_iv).unwrap();
        assert_eq!(indexed_value_to_keywords, res);

        //
        // Non regression vector
        //
        let non_reg_vector = vec![
            1, 9, 108, 0, 0, 0, 0, 0, 0, 0, 0, 1, 5, 70, 101, 108, 105, 120,
        ];
        let _res = deserialize_indexed_values(&non_reg_vector).unwrap();
    }

    #[test]
    fn test_edx_lines_serialization() {
        let edx_lines = HashMap::<Token, EncryptedValue<{ Token::LENGTH }>>::from_iter([
            (
                Token::from([0; Token::LENGTH]),
                EncryptedValue::try_from(
                    vec![0; EncryptedValue::<{ Token::LENGTH }>::LENGTH].as_slice(),
                )
                .unwrap(),
            ),
            (
                Token::from([1; Token::LENGTH]),
                EncryptedValue::try_from(
                    vec![1; EncryptedValue::<{ Token::LENGTH }>::LENGTH].as_slice(),
                )
                .unwrap(),
            ),
            (
                Token::from([2; Token::LENGTH]),
                EncryptedValue::try_from(
                    vec![2; EncryptedValue::<{ Token::LENGTH }>::LENGTH].as_slice(),
                )
                .unwrap(),
            ),
            (
                Token::from([3; Token::LENGTH]),
                EncryptedValue::try_from(
                    vec![3; EncryptedValue::<{ Token::LENGTH }>::LENGTH].as_slice(),
                )
                .unwrap(),
            ),
            (
                Token::from([4; Token::LENGTH]),
                EncryptedValue::try_from(
                    vec![4; EncryptedValue::<{ Token::LENGTH }>::LENGTH].as_slice(),
                )
                .unwrap(),
            ),
            (
                Token::from([5; Token::LENGTH]),
                EncryptedValue::try_from(
                    vec![5; EncryptedValue::<{ Token::LENGTH }>::LENGTH].as_slice(),
                )
                .unwrap(),
            ),
        ]);

        let serialized_lines =
            serialize_edx_lines(&TokenToEncryptedValueMap::from(edx_lines.clone())).unwrap();
        let res = deserialize_edx_lines(&serialized_lines).unwrap();
        assert_eq!(edx_lines, res.into_iter().collect());
    }
}
