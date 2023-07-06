use cosmian_cover_crypt::{
    abe_policy::{AccessPolicy, Policy},
    Covercrypt, MasterSecretKey,
};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

/// Generate the master authority keys for supplied Policy
///
/// - `policy`  : global policy data (JSON)
#[wasm_bindgen]
pub fn webassembly_generate_master_keys(policy_bytes: Vec<u8>) -> Result<Uint8Array, JsValue> {
    let policy = wasm_unwrap!(
        Policy::parse_and_convert(&policy_bytes,),
        "Error deserializing policy"
    );

    //
    // Setup CoverCrypt
    let (msk, mpk) = wasm_unwrap!(
        Covercrypt::default().generate_master_keys(&policy),
        "Error generating master keys"
    );

    // Serialize master keys
    let msk_bytes = wasm_unwrap!(msk.serialize(), "Error serializing master secret key");
    let mpk_bytes = wasm_unwrap!(mpk.serialize(), "Error serializing master public key");

    let mut master_keys_bytes = Vec::with_capacity(4 + msk_bytes.len() + msk_bytes.len());
    master_keys_bytes.extend_from_slice(&u32::to_be_bytes(wasm_unwrap!(
        msk_bytes.len().try_into(),
        "Error while converting usize to u32"
    )));
    master_keys_bytes.extend_from_slice(&msk_bytes);
    master_keys_bytes.extend_from_slice(&mpk_bytes);
    Ok(Uint8Array::from(&master_keys_bytes[..]))
}

/// Generate a user secret key.
///
/// - `msk_bytes`           : master secret key in bytes
/// - `access_policy_str`   : user access policy (boolean expression as string)
/// - `policy`              : global policy data (JSON)
#[wasm_bindgen]
pub fn webassembly_generate_user_secret_key(
    msk_bytes: Uint8Array,
    access_policy_str: &str,
    policy_bytes: Vec<u8>,
) -> Result<Uint8Array, JsValue> {
    let msk = wasm_unwrap!(
        MasterSecretKey::deserialize(&msk_bytes.to_vec()),
        "Error deserializing master secret key"
    );
    let policy = wasm_unwrap!(
        Policy::parse_and_convert(&policy_bytes),
        "Error deserializing policy"
    );
    let access_policy = wasm_unwrap!(
        AccessPolicy::from_boolean_expression(access_policy_str),
        "Error deserializing access policy"
    );
    let user_key = wasm_unwrap!(
        Covercrypt::default().generate_user_secret_key(&msk, &access_policy, &policy),
        "Error generating user secret key"
    );
    let user_key_bytes = wasm_unwrap!(user_key.serialize(), "Error serializing user key");
    Ok(Uint8Array::from(user_key_bytes.as_slice()))
}
