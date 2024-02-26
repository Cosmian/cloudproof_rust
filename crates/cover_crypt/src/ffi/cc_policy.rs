use cosmian_cover_crypt::abe_policy::{
    AccessPolicy, Attribute, DimensionBuilder, EncryptionHint, Policy,
};
use cosmian_ffi_utils::{ffi_read_bytes, ffi_read_string, ffi_unwrap, ffi_write_bytes, ErrorCode};

/// This macro handles deserializing the policy from JS, deserializing an
/// attribute from JS, and performing a specified action on the policy. It also
/// ensures proper error handling and serialization of the updated policy into
/// the response.
///
///
/// # Parameters
///
/// - `$updated_policy_ptr`: output serialized updated policy.
/// - `$updated_policy_len`: output serialized updated policy length.
/// - `$current_policy_ptr`: serialized policy to update.
/// - `$current_policy_len`: serialized policy length to update.
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
        $updated_policy_ptr:ident,
        $updated_policy_len:ident,
        $current_policy_ptr:ident,
        $current_policy_len:ident,
        $attr_bytes:ident,
        $cc_policy:ident,
        $cc_attr:ident,
        $action:expr,
        $error_msg:expr
    ) => {{
        let policy_bytes =
            ffi_read_bytes!("current policy", $current_policy_ptr, $current_policy_len);
        let mut $cc_policy = ffi_unwrap!(
            Policy::parse_and_convert(policy_bytes),
            "error deserializing policy",
            ErrorCode::Serialization
        );

        let attr_string = ffi_read_string!("attribute", $attr_bytes);
        let $cc_attr = ffi_unwrap!(
            Attribute::try_from(attr_string.as_str()),
            "error parsing attribute",
            ErrorCode::InvalidArgument("Attribute".to_string())
        );

        ffi_unwrap!($action, $error_msg, ErrorCode::Serialization);

        let policy_bytes = ffi_unwrap!(
            <Vec<u8>>::try_from(&$cc_policy),
            "error serializing policy",
            ErrorCode::Serialization
        );
        ffi_write_bytes!(
            "updated policy",
            &policy_bytes,
            $updated_policy_ptr,
            $updated_policy_len
        );
    }};
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn h_policy(policy_ptr: *mut i8, policy_len: *mut i32) -> i32 {
    let policy = Policy::new();
    let policy_bytes = ffi_unwrap!(
        <Vec<u8>>::try_from(&policy),
        "error deserializing policy",
        ErrorCode::Serialization
    );
    ffi_write_bytes!("policy", &policy_bytes, policy_ptr, policy_len);
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn h_add_policy_axis(
    updated_policy_ptr: *mut i8,
    updated_policy_len: *mut i32,
    current_policy_ptr: *const i8,
    current_policy_len: i32,
    axis_ptr: *const i8,
) -> i32 {
    let policy_bytes = ffi_read_bytes!("current policy", current_policy_ptr, current_policy_len);
    let mut policy = ffi_unwrap!(
        Policy::parse_and_convert(policy_bytes),
        "error deserializing policy",
        ErrorCode::Serialization
    );
    let axis_string = ffi_read_string!("axis", axis_ptr);
    let axis: DimensionBuilder = ffi_unwrap!(
        serde_json::from_str(&axis_string),
        "error deserializing policy axis",
        ErrorCode::Serialization
    );

    ffi_unwrap!(
        policy.add_dimension(axis),
        "error adding policy axis",
        ErrorCode::CovercryptPolicy
    );

    let policy_bytes = ffi_unwrap!(
        <Vec<u8>>::try_from(&policy),
        "error serializing policy",
        ErrorCode::Serialization
    );
    ffi_write_bytes!(
        "updated policy",
        &policy_bytes,
        updated_policy_ptr,
        updated_policy_len
    );
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn h_remove_policy_axis(
    updated_policy_ptr: *mut i8,
    updated_policy_len: *mut i32,
    current_policy_ptr: *const i8,
    current_policy_len: i32,
    axis_name_ptr: *const i8,
) -> i32 {
    let policy_bytes = ffi_read_bytes!("current policy", current_policy_ptr, current_policy_len);
    let mut policy = ffi_unwrap!(
        Policy::parse_and_convert(policy_bytes),
        "error deserializing policy",
        ErrorCode::Serialization
    );

    let axis_name = ffi_read_string!("axis name", axis_name_ptr);

    ffi_unwrap!(
        policy.remove_dimension(&axis_name),
        "error removing policy axis",
        ErrorCode::CovercryptPolicy
    );

    let policy_bytes = ffi_unwrap!(
        <Vec<u8>>::try_from(&policy),
        "error serializing policy",
        ErrorCode::Serialization
    );
    ffi_write_bytes!(
        "updated policy",
        &policy_bytes,
        updated_policy_ptr,
        updated_policy_len
    );
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn h_add_policy_attribute(
    updated_policy_ptr: *mut i8,
    updated_policy_len: *mut i32,
    current_policy_ptr: *const i8,
    current_policy_len: i32,
    attribute: *const i8,
    is_hybridized: bool,
) -> i32 {
    update_policy!(
        updated_policy_ptr,
        updated_policy_len,
        current_policy_ptr,
        current_policy_len,
        attribute,
        cc_policy,
        cc_attr,
        cc_policy.add_attribute(cc_attr, EncryptionHint::new(is_hybridized)),
        "error adding policy attribute"
    )
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn h_remove_policy_attribute(
    updated_policy_ptr: *mut i8,
    updated_policy_len: *mut i32,
    current_policy_ptr: *const i8,
    current_policy_len: i32,
    attribute: *const i8,
) -> i32 {
    update_policy!(
        updated_policy_ptr,
        updated_policy_len,
        current_policy_ptr,
        current_policy_len,
        attribute,
        cc_policy,
        cc_attr,
        cc_policy.remove_attribute(&cc_attr),
        "error removing policy attribute"
    )
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn h_disable_policy_attribute(
    updated_policy_ptr: *mut i8,
    updated_policy_len: *mut i32,
    current_policy_ptr: *const i8,
    current_policy_len: i32,
    attribute: *const i8,
) -> i32 {
    update_policy!(
        updated_policy_ptr,
        updated_policy_len,
        current_policy_ptr,
        current_policy_len,
        attribute,
        cc_policy,
        cc_attr,
        cc_policy.disable_attribute(&cc_attr),
        "error disabling policy attribute"
    )
}

#[no_mangle]
pub unsafe extern "C" fn h_rename_policy_attribute(
    updated_policy_ptr: *mut i8,
    updated_policy_len: *mut i32,
    current_policy_ptr: *const i8,
    current_policy_len: i32,
    attribute: *const i8,
    new_attribute_name_ptr: *const i8,
) -> i32 {
    let new_attribute_name = ffi_read_string!("new attribute name", new_attribute_name_ptr);

    update_policy!(
        updated_policy_ptr,
        updated_policy_len,
        current_policy_ptr,
        current_policy_len,
        attribute,
        cc_policy,
        cc_attr,
        cc_policy.rename_attribute(&cc_attr, new_attribute_name),
        "error renaming policy attribute"
    )
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn h_validate_boolean_expression(boolean_expression_ptr: *const i8) -> i32 {
    let boolean_expression = ffi_read_string!("boolean expression", boolean_expression_ptr);
    ffi_unwrap!(
        AccessPolicy::from_boolean_expression(&boolean_expression),
        "error parsing boolean expression",
        ErrorCode::Serialization
    );
    0
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn h_validate_attribute(attribute_ptr: *const i8) -> i32 {
    let attribute_str = ffi_read_string!("attribute", attribute_ptr);
    ffi_unwrap!(
        AccessPolicy::from_boolean_expression(&attribute_str),
        "error parsing attribute",
        ErrorCode::Serialization
    );
    0
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use cosmian_cover_crypt::test_utils::policy;

    use super::*;

    #[test]
    fn test_create_policy() {
        let policy = Policy::new();
        let mut policy_bytes = <Vec<u8>>::try_from(&policy).unwrap();

        let ordered_dim = r#"{ "name": "Security Level", "attributes_properties": [{ "name": "Protected", "encryption_hint": "Classic" }, { "name": "Confidential", "encryption_hint": "Classic" }, { "name": "Top Secret", "encryption_hint": "Hybridized" }], "hierarchical": true }"#.to_string();
        policy_bytes = unsafe {
            let current_policy_ptr = policy_bytes.as_ptr().cast();
            let current_policy_len = policy_bytes.len() as i32;
            let mut updated_policy_bytes = vec![0u8; 4096];
            let updated_policy_ptr = updated_policy_bytes.as_mut_ptr().cast();
            let mut updated_policy_len = updated_policy_bytes.len() as i32;
            let res = h_add_policy_axis(
                updated_policy_ptr,
                &mut updated_policy_len,
                current_policy_ptr,
                current_policy_len,
                ordered_dim.as_ptr().cast(),
            );
            assert_eq!(res, 0);
            std::slice::from_raw_parts(updated_policy_ptr.cast(), updated_policy_len as usize)
                .to_vec()
        };

        let ffi_policy = Policy::parse_and_convert(&policy_bytes).unwrap();
        let ffi_attributes = ffi_policy.attributes();

        // Check policy size
        assert_eq!(ffi_attributes.len(), 3);

        // Check order
        assert_eq!(
            ffi_attributes
                .into_iter()
                .map(|attr| attr.name)
                .collect::<Vec<_>>(),
            vec!["Protected", "Confidential", "Top Secret"]
        );
    }

    #[test]
    fn test_edit_policy() {
        let policy = policy().unwrap();
        let mut policy_bytes = <Vec<u8>>::try_from(&policy).unwrap();
        let attributes = policy.attributes();

        assert_eq!(attributes.len(), 9);
        // Remove Security Level axis
        policy_bytes = unsafe {
            let current_policy_ptr = policy_bytes.as_ptr().cast();
            let current_policy_len = policy_bytes.len() as i32;
            let mut updated_policy_bytes = vec![0u8; 8192];
            let updated_policy_ptr = updated_policy_bytes.as_mut_ptr().cast();
            let mut updated_policy_len = updated_policy_bytes.len() as i32;
            let axis_name = "Security Level".to_string();

            let res = h_remove_policy_axis(
                updated_policy_ptr,
                &mut updated_policy_len,
                current_policy_ptr,
                current_policy_len,
                axis_name.as_ptr().cast(),
            );
            assert_eq!(res, 0);
            std::slice::from_raw_parts(updated_policy_ptr.cast(), updated_policy_len as usize)
                .to_vec()
        };

        let ffi_edited_policy = Policy::parse_and_convert(&policy_bytes).unwrap();
        let ffi_attributes = ffi_edited_policy.attributes();
        // Check policy size
        assert_eq!(ffi_attributes.len(), 4);

        // Add attribute Sales
        policy_bytes = unsafe {
            let current_policy_ptr = policy_bytes.as_ptr().cast();
            let current_policy_len = policy_bytes.len() as i32;
            let mut updated_policy_bytes = vec![0u8; 8192];
            let updated_policy_ptr = updated_policy_bytes.as_mut_ptr().cast();
            let mut updated_policy_len = updated_policy_bytes.len() as i32;
            let attr = Attribute::new("Department", "Sales");
            let c_attr = CString::new(attr.to_string()).unwrap();

            let res = h_add_policy_attribute(
                updated_policy_ptr,
                &mut updated_policy_len,
                current_policy_ptr,
                current_policy_len,
                c_attr.as_ptr().cast(),
                false,
            );
            assert_eq!(res, 0);
            std::slice::from_raw_parts(updated_policy_ptr.cast(), updated_policy_len as usize)
                .to_vec()
        };

        let ffi_edited_policy = Policy::parse_and_convert(&policy_bytes).unwrap();
        let ffi_attributes = ffi_edited_policy.attributes();
        // Check policy size
        assert_eq!(ffi_attributes.len(), 5);

        // Remove attribute
        policy_bytes = unsafe {
            let current_policy_ptr = policy_bytes.as_ptr().cast();
            let current_policy_len = policy_bytes.len() as i32;
            let mut updated_policy_bytes = vec![0u8; 8192];
            let updated_policy_ptr = updated_policy_bytes.as_mut_ptr().cast();
            let mut updated_policy_len = updated_policy_bytes.len() as i32;
            let attr = Attribute::new("Department", "R&D");
            let c_attr = CString::new(attr.to_string()).unwrap();

            let res = h_remove_policy_attribute(
                updated_policy_ptr,
                &mut updated_policy_len,
                current_policy_ptr,
                current_policy_len,
                c_attr.as_ptr().cast(),
            );
            assert_eq!(res, 0);
            std::slice::from_raw_parts(updated_policy_ptr.cast(), updated_policy_len as usize)
                .to_vec()
        };

        let ffi_edited_policy = Policy::parse_and_convert(&policy_bytes).unwrap();
        let ffi_attributes = ffi_edited_policy.attributes();
        // Check policy size
        assert_eq!(ffi_attributes.len(), 4);

        // Disable attribute
        policy_bytes = unsafe {
            let current_policy_ptr = policy_bytes.as_ptr().cast();
            let current_policy_len = policy_bytes.len() as i32;
            let mut updated_policy_bytes = vec![0u8; 8192];
            let updated_policy_ptr = updated_policy_bytes.as_mut_ptr().cast();
            let mut updated_policy_len = updated_policy_bytes.len() as i32;
            let attr = Attribute::new("Department", "MKG");
            let c_attr = CString::new(attr.to_string()).unwrap();

            let res = h_disable_policy_attribute(
                updated_policy_ptr,
                &mut updated_policy_len,
                current_policy_ptr,
                current_policy_len,
                c_attr.as_ptr().cast(),
            );
            assert_eq!(res, 0);
            std::slice::from_raw_parts(updated_policy_ptr.cast(), updated_policy_len as usize)
                .to_vec()
        };

        let ffi_edited_policy = Policy::parse_and_convert(&policy_bytes).unwrap();
        let ffi_attributes = ffi_edited_policy.attributes();
        // Check policy size
        assert_eq!(ffi_attributes.len(), 4);

        // Rename attribute
        policy_bytes = unsafe {
            let current_policy_ptr = policy_bytes.as_ptr().cast();
            let current_policy_len = policy_bytes.len() as i32;
            let mut updated_policy_bytes = vec![0u8; 8192];
            let updated_policy_ptr = updated_policy_bytes.as_mut_ptr().cast();
            let mut updated_policy_len = updated_policy_bytes.len() as i32;
            let attr = Attribute::new("Department", "FIN");
            let c_attr = CString::new(attr.to_string()).unwrap();
            let c_new_attribute_name = CString::new("Finance".to_string()).unwrap();

            let res = h_rename_policy_attribute(
                updated_policy_ptr,
                &mut updated_policy_len,
                current_policy_ptr,
                current_policy_len,
                c_attr.as_ptr().cast(),
                c_new_attribute_name.as_ptr().cast(),
            );
            assert_eq!(res, 0);
            std::slice::from_raw_parts(updated_policy_ptr.cast(), updated_policy_len as usize)
                .to_vec()
        };

        let ffi_edited_policy = Policy::parse_and_convert(&policy_bytes).unwrap();
        let ffi_attributes = ffi_edited_policy.attributes();
        // Check policy size
        assert_eq!(ffi_attributes.len(), 4);
    }
}
