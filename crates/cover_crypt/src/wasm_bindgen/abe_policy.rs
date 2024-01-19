use cosmian_cover_crypt::abe_policy::{Attribute, DimensionBuilder, EncryptionHint, Policy};
use js_sys::{Array, Boolean, JsString, Reflect};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

/// This macro handles deserializing the policy from JS, deserializing an
/// attribute from JS, and performing a specified action on the policy. It also
/// ensures proper error handling and serialization of the updated policy into
/// the response.
///
///
/// # Parameters
///
/// - `$policy_bytes`: serialized policy to update.
/// - `$attr_bytes`: serialized attribute to be processed.
/// - `$cc_policy`: placeholder name for the deserialized policy.
/// - `$cc_attr`: placeholder name for the deserialized attribute.
/// - `$action`: action to perform on the policy.
/// - `$error_msg`: error message to display in case of failures.
///
/// # Returns
///
/// The serialized updated Policy.
/// ```
macro_rules! update_policy {
    (
        $policy_bytes:ident,
        $attr_bytes:ident,
        $cc_policy:ident,
        $cc_attr:ident,
        $action:expr,
        $error_msg:expr
    ) => {{
        let mut $cc_policy = wasm_unwrap!(
            Policy::parse_and_convert(&$policy_bytes),
            "Error deserializing the policy"
        );
        let $cc_attr = wasm_unwrap!(
            Attribute::try_from(String::from(JsString::from($attr_bytes)).as_str()),
            "Error deserializing the attribute"
        );

        wasm_unwrap!($action, $error_msg);
        serde_json::to_vec(&$cc_policy).map_err(|e| {
            JsValue::from_str(&format!(
                "Error serializing the policy into the response: {e}"
            ))
        })
    }};
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Array<string>")]
    pub type Attributes;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "{name: string, isHybridized: boolean}")]
    pub type AttributeProperty;
}

#[wasm_bindgen]
pub fn webassembly_policy_axis(
    name: String,
    attribute_properties: Vec<AttributeProperty>,
    is_hierarchical: bool,
) -> Result<String, JsValue> {
    let attribute_properties = attribute_properties
        .into_iter()
        .map(|obj| -> Result<(String, EncryptionHint), JsValue> {
            let name = String::from(JsString::from(Reflect::get(
                &obj,
                &JsValue::from_str("name"),
            )?));
            let encryption_hint = bool::from(Boolean::from(Reflect::get(
                &obj,
                &JsValue::from_str("name"),
            )?));
            let encryption_hint = if encryption_hint {
                EncryptionHint::Hybridized
            } else {
                EncryptionHint::Classic
            };
            Ok((name, encryption_hint))
        })
        .collect::<Result<Vec<_>, _>>()?;

    serde_json::to_string(&DimensionBuilder::new(
        &name,
        attribute_properties
            .iter()
            .map(|(name, encryption_hint)| (name.as_str(), *encryption_hint))
            .collect(),
        is_hierarchical,
    ))
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn webassembly_policy() -> Result<Vec<u8>, JsValue> {
    serde_json::to_vec(&Policy::new()).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn webassembly_add_axis(policy: Vec<u8>, axis: String) -> Result<Vec<u8>, JsValue> {
    let mut cc_policy = wasm_unwrap!(
        Policy::parse_and_convert(&policy),
        "Error deserializing the policy"
    );
    wasm_unwrap!(
        cc_policy.add_dimension(wasm_unwrap!(
            serde_json::from_str(&axis),
            "Error deserializing the policy axis"
        )),
        "Error adding axis to the policy"
    );
    serde_json::to_vec(&cc_policy).map_err(|e| {
        JsValue::from_str(&format!(
            "Error serializing the policy into the response: {e}"
        ))
    })
}

#[wasm_bindgen]
pub fn webassembly_remove_axis(policy: Vec<u8>, axis_name: &str) -> Result<Vec<u8>, JsValue> {
    let mut cc_policy = wasm_unwrap!(
        Policy::parse_and_convert(&policy),
        "Error deserializing the policy"
    );
    wasm_unwrap!(
        cc_policy.remove_dimension(axis_name),
        "Error removing axis from the policy"
    );
    serde_json::to_vec(&cc_policy).map_err(|e| {
        JsValue::from_str(&format!(
            "Error serializing the policy into the response: {e}"
        ))
    })
}

#[wasm_bindgen]
pub fn webassembly_add_attribute(
    policy: Vec<u8>,
    attribute: String,
    is_hybridized: bool,
) -> Result<Vec<u8>, JsValue> {
    update_policy!(
        policy,
        attribute,
        cc_policy,
        cc_attr,
        cc_policy.add_attribute(cc_attr, EncryptionHint::new(is_hybridized)),
        "Error adding attribute to the policy"
    )
}

#[wasm_bindgen]
pub fn webassembly_remove_attribute(
    policy: Vec<u8>,
    attribute: String,
) -> Result<Vec<u8>, JsValue> {
    update_policy!(
        policy,
        attribute,
        cc_policy,
        cc_attr,
        cc_policy.remove_attribute(&cc_attr),
        "Error removing attribute from the policy"
    )
}

#[wasm_bindgen]
pub fn webassembly_disable_attribute(
    policy: Vec<u8>,
    attribute: String,
) -> Result<Vec<u8>, JsValue> {
    update_policy!(
        policy,
        attribute,
        cc_policy,
        cc_attr,
        cc_policy.disable_attribute(&cc_attr),
        "Error disabling attribute from the policy"
    )
}

#[wasm_bindgen]
pub fn webassembly_rename_attribute(
    policy: Vec<u8>,
    attribute: String,
    new_attribute_name: String,
) -> Result<Vec<u8>, JsValue> {
    let new_name = String::from(JsString::from(new_attribute_name));
    update_policy!(
        policy,
        attribute,
        cc_policy,
        cc_attr,
        cc_policy.rename_attribute(&cc_attr, new_name),
        "Error renaming attribute from the policy"
    )
}

/// Rotates attributes, changing their underlying values with that of an unused
/// slot
///
/// - `attributes`  : list of attributes to rotate
/// - `policy`      : global policy data (bytes)
///
/// Returns the `rotated` policy
#[wasm_bindgen]
pub fn webassembly_rotate_attributes(
    attributes: Attributes,
    policy: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let attributes = Array::from(&JsValue::from(attributes));
    let mut cc_policy = wasm_unwrap!(
        Policy::parse_and_convert(&policy),
        "Error deserializing the policy"
    );

    todo!();

    serde_json::to_vec(&cc_policy).map_err(|e| {
        JsValue::from_str(&format!(
            "Error serializing the policy into the response: {e}"
        ))
    })
}

#[wasm_bindgen]
pub fn webassembly_clear_old_attribute_values(
    attributes: Attributes,
    policy: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let attributes = Array::from(&JsValue::from(attributes));
    let mut cc_policy = wasm_unwrap!(
        Policy::parse_and_convert(&policy),
        "Error deserializing the policy"
    );

    todo!();

    serde_json::to_vec(&cc_policy).map_err(|e| {
        JsValue::from_str(&format!(
            "Error serializing the policy into the response: {e}"
        ))
    })
}
