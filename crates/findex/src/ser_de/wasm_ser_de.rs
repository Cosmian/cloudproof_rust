use std::collections::HashSet;

use cosmian_findex::{EncryptedValue, Token, TokenToEncryptedValueMap, Tokens};
use js_sys::{Array, JsString, Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};

use super::SerializationError;

fn set_bytes_in_object_property(
    obj: &JsValue,
    property: &str,
    value: &[u8],
) -> Result<bool, JsValue> {
    let js_value = unsafe { JsValue::from(Uint8Array::new(&Uint8Array::view(value))) };
    Reflect::set(obj, &JsValue::from_str(property), &js_value)
}

pub fn get_bytes_from_object_property(value: &JsValue, property: &str) -> Result<Vec<u8>, JsValue> {
    if !value.is_object() {
        return Err(JsValue::from_str(
            format!("{} found while an object expected.", get_js_type(value)).as_str(),
        ));
    };

    let bytes = Reflect::get(value, &JsValue::from_str(property))?;
    if bytes.is_undefined() {
        return Err(JsValue::from_str(
            format!(" `{property}` property not found",).as_str(),
        ));
    }

    Ok(Uint8Array::from(bytes).to_vec())
}

fn get_js_type(value: &JsValue) -> String {
    value
        .js_typeof()
        .dyn_ref::<JsString>()
        .map_or_else(|| "unknown type".to_owned(), |s| format!("{s}"))
}

/// Converts the given set of UIDs into a Js array.
pub fn uids_to_js_array(uids: &Tokens) -> Result<Array, SerializationError> {
    let js_uids = Array::new();
    for uid in uids.iter() {
        let js_uid = unsafe { Uint8Array::new(&Uint8Array::view(uid)) };
        js_uids.push(&js_uid);
    }
    Ok(js_uids)
}

/// Converts the given Js value (as Js array) into a set of UIDs.
pub fn js_value_to_uids(js_value: &JsValue) -> Result<Tokens, SerializationError> {
    if !Array::is_array(js_value) {
        return Err(SerializationError(format!(
            "{} found while an array was expected",
            get_js_type(js_value)
        )));
    }
    let js_array = Array::from(js_value);

    let mut res = HashSet::with_capacity(js_array.length() as usize);
    for uid in js_array {
        res.insert(Token::try_from(Uint8Array::from(uid).to_vec().as_slice())?);
    }
    Ok(Tokens::from(res))
}

/// Converts the given Js value (as Js array) into set of EDX lines.
pub fn js_value_to_edx_lines<const VALUE_LENGTH: usize>(
    js_value: &JsValue,
) -> Result<Vec<(Token, EncryptedValue<VALUE_LENGTH>)>, SerializationError> {
    if !Array::is_array(js_value) {
        return Err(SerializationError(format!(
            "{} found while an array was expected",
            get_js_type(js_value)
        )));
    }
    let js_array = Array::from(js_value);

    let mut edx_lines = Vec::with_capacity(js_array.length() as usize);

    for (i, try_obj) in js_array.values().into_iter().enumerate() {
        let obj = try_obj?;

        if !obj.is_object() {
            return Err(SerializationError(format!(
                "{} found while an object expected",
                get_js_type(&obj)
            )));
        }

        let uid = get_bytes_from_object_property(&obj, "uid")?;
        let value = get_bytes_from_object_property(&obj, "value")?;

        edx_lines.push((
            Token::try_from(uid.as_slice()).map_err(|uid| {
                SerializationError(format!(
                    "`uid` at position {i} ({uid:?}) is not a valid UID"
                ))
            })?,
            EncryptedValue::<VALUE_LENGTH>::try_from(value.as_slice()).map_err(|e| {
                SerializationError(format!(
                    "`value` at position {i} is not a valid EncryptedValue ({e})"
                ))
            })?,
        ));
    }

    Ok(edx_lines)
}

/// Converts the given set of EDX lines into a Js array.
pub fn edx_lines_to_js_array<const VALUE_LENGTH: usize>(
    edx_lines: &TokenToEncryptedValueMap<VALUE_LENGTH>,
) -> Result<Array, SerializationError> {
    let res = Array::new_with_length(edx_lines.len() as u32);
    for (index, (uid, value)) in edx_lines.iter().enumerate() {
        let obj = Object::new();
        set_bytes_in_object_property(&obj, "uid", uid)?;
        set_bytes_in_object_property(&obj, "value", <Vec<u8>>::from(value).as_slice())?;
        res.set(index as u32, obj.into());
    }
    Ok(res)
}

#[cfg(test)]
mod tests {

    use cosmian_findex::{Token, Tokens};
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[wasm_bindgen_test]
    fn test_uid_set_serialization() {
        let uids = Tokens::from_iter([
            Token::from([0; Token::LENGTH]),
            Token::from([1; Token::LENGTH]),
            Token::from([2; Token::LENGTH]),
            Token::from([3; Token::LENGTH]),
            Token::from([4; Token::LENGTH]),
            Token::from([5; Token::LENGTH]),
        ]);

        let js_uids = uids_to_js_array(&uids).unwrap();
        let res = js_value_to_uids(&JsValue::from(&js_uids)).unwrap();
        assert_eq!(uids, res);
    }

    #[wasm_bindgen_test]
    fn test_edx_lines_serialization() {
        let uids: cosmian_findex::TokenToEncryptedValueMap<{ Token::LENGTH }> =
            TokenToEncryptedValueMap::from_iter([
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

        let js_uids = edx_lines_to_js_array(&uids).unwrap();
        let res = js_value_to_edx_lines(&JsValue::from(&js_uids)).unwrap();
        assert_eq!(uids, res.into_iter().collect());
    }
}
