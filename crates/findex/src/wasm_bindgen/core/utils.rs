use std::collections::HashSet;

use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_findex::{EncryptedTable, Uid};
use js_sys::{Array, JsString, Object, Reflect, Uint8Array};
pub use js_sys::{Function, Promise};
use wasm_bindgen::JsCast;
pub use wasm_bindgen::JsValue;
use wasm_bindgen_futures;

use crate::wasm_bindgen::{
    core::{types::ObjectSourceForErrors, Fetch},
    FindexWasmError,
};

/// Makes sure the given callback exists in the given Findex instance.
///
/// - `findex`      : name of the findex instance
/// - `callback`    : name of the callback
macro_rules! unwrap_callback {
    ($findex:ident, $callback:ident) => {
        $findex.$callback.as_ref().ok_or_else(|| {
            FindexWasmError::MissingCallback(format!(
                "No attribute `{}` is defined for `self`",
                stringify!($callback)
            ))
        })?
    };
}

/// Call the WASM callback.
macro_rules! callback {
    ($callback_ref:expr, $input:ident) => {{
        let this = &$crate::wasm_bindgen::core::utils::JsValue::null();
        let js_function = $crate::wasm_bindgen::core::utils::Function::from(
            $crate::wasm_bindgen::core::utils::JsValue::from($callback_ref),
        );
        let promise =
            $crate::wasm_bindgen::core::utils::Promise::resolve(&js_function.call1(this, &$input)?);
        wasm_bindgen_futures::JsFuture::from(promise).await?
    }};
}

/// Fetch all items matching the given uids.
///
/// - `uids`         : the uids to fetch
/// - `fetch_entries`: JS callback calling the DB
#[inline]
pub async fn fetch_uids<const UID_LENGTH: usize>(
    uids: &HashSet<Uid<UID_LENGTH>>,
    fetch_callback: &Fetch,
    source_for_errors: &'static str,
) -> Result<EncryptedTable<UID_LENGTH>, FindexWasmError> {
    // Convert Inputs to array of Uint8Array
    let input = Array::new();
    for uid in uids {
        let js_uid = unsafe { Uint8Array::new(&Uint8Array::view(uid)) };
        input.push(&js_uid);
    }

    // perform the call
    let output = callback!(fetch_callback, input);

    // parse results into HashMap
    js_value_to_encrypted_table(&output, source_for_errors).map_err(FindexWasmError::from)
}

#[inline]
pub fn set_bytes_in_object_property(
    obj: &JsValue,
    property: &str,
    value: Option<&[u8]>,
) -> Result<bool, JsValue> {
    js_sys::Reflect::set(obj, &JsValue::from_str(property), unsafe {
        &value.map_or_else(JsValue::null, |bytes| {
            JsValue::from(Uint8Array::new(&Uint8Array::view(bytes)))
        })
    })
}

pub fn js_value_to_encrypted_table<const UID_LENGTH: usize>(
    encrypted_table: &JsValue,
    callback_name_for_errors: &'static str,
) -> Result<EncryptedTable<UID_LENGTH>, JsValue> {
    if !Array::is_array(encrypted_table) {
        return Err(JsValue::from_str(
            format!(
                "return value of {callback_name_for_errors} is of type {}, array expected",
                encrypted_table
                    .js_typeof()
                    .dyn_ref::<JsString>()
                    .map_or_else(|| "unknown type".to_owned(), |s| format!("{s}")),
            )
            .as_str(),
        ));
    }

    let array = Array::from(encrypted_table);
    let mut encrypted_table = EncryptedTable::<UID_LENGTH>::with_capacity(array.length() as usize);
    let object_source_for_errors =
        ObjectSourceForErrors::ReturnedFromCallback(callback_name_for_errors);
    for (i, try_obj) in array.values().into_iter().enumerate() {
        let obj = try_obj?;

        if !obj.is_object() {
            return Err(JsValue::from_str(
                format!(
                    "{object_source_for_errors}, position {i} contains {}, object expected.",
                    obj.js_typeof()
                        .dyn_ref::<JsString>()
                        .map_or_else(|| "unknown type".to_owned(), |s| format!("{s}")),
                )
                .as_str(),
            ));
        }

        let uid = get_bytes_from_object_property(&obj, "uid", &object_source_for_errors, i)?;

        let value = get_bytes_from_object_property(&obj, "value", &object_source_for_errors, i)?;
        encrypted_table.insert(
            Uid::try_from_bytes(&uid).map_err(|e| {
                JsValue::from_str(
                    format!(
                        "cannot parse the `uid` returned by `{callback_name_for_errors}` at \
                         position {i} ({e}). `uid` as hex was '{}'.",
                        hex::encode(uid),
                    )
                    .as_str(),
                )
            })?,
            value.clone(),
        );
    }
    Ok(encrypted_table)
}

pub fn encrypted_table_to_js_value<const UID_LENGTH: usize>(
    encrypted_table: &EncryptedTable<UID_LENGTH>,
) -> Result<Array, JsValue> {
    let res = Array::new_with_length(encrypted_table.len() as u32);
    for (index, (uid, value)) in encrypted_table.iter().enumerate() {
        let obj = Object::new();
        set_bytes_in_object_property(&obj, "uid", Some(uid))?;
        set_bytes_in_object_property(&obj, "value", Some(value))?;
        res.set(index as u32, obj.into());
    }
    Ok(res)
}

pub fn get_bytes_from_object_property(
    obj: &JsValue,
    property: &str,
    object_source_for_errors: &ObjectSourceForErrors,
    position_in_array_for_errors: usize,
) -> Result<Vec<u8>, JsValue> {
    obj.dyn_ref::<Object>().ok_or_else(|| {
        JsValue::from_str(
            format!(
                "{object_source_for_errors}, position {position_in_array_for_errors} contains {}, \
                 object expected.",
                obj.js_typeof()
                    .dyn_ref::<JsString>()
                    .map_or_else(|| "unknown type".to_owned(), |s| format!("{s}")),
            )
            .as_str(),
        )
    })?;

    let bytes = Reflect::get(obj, &JsValue::from_str(property))?;

    if bytes.is_undefined() {
        return Err(JsValue::from_str(
            format!(
                "{object_source_for_errors}, position {position_in_array_for_errors} contains an \
                 object without a `{property}` property.",
            )
            .as_str(),
        ));
    }

    Ok(Uint8Array::from(bytes).to_vec())
}
