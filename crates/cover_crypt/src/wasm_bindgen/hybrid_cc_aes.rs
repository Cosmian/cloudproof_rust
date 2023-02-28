// needed to remove wasm_bindgen warnings
#![allow(non_upper_case_globals)]

use cosmian_cover_crypt::{
    abe_policy::AccessPolicy,
    statics::{CoverCryptX25519Aes256, EncryptedHeader, PublicKey, UserSecretKey, DEM},
    CoverCrypt,
};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    symmetric_crypto::{Dem, SymKey},
    KeyTrait,
};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

pub const MAX_CLEAR_TEXT_SIZE: usize = 1 << 30;

#[wasm_bindgen]
pub fn webassembly_encrypt_hybrid_header(
    policy_bytes: Vec<u8>,
    access_policy: String,
    public_key_bytes: Uint8Array,
    header_metadata: Uint8Array,
    authentication_data: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let policy = wasm_unwrap!(
        serde_json::from_slice(&policy_bytes),
        "Error deserializing policy"
    );
    let access_policy = wasm_unwrap!(
        AccessPolicy::from_boolean_expression(&access_policy),
        "Error reading access policy"
    );
    let public_key = wasm_unwrap!(
        PublicKey::try_from_bytes(&public_key_bytes.to_vec()),
        "Error deserializing public key"
    );
    let header_metadata = if header_metadata.is_null() {
        None
    } else {
        Some(header_metadata.to_vec())
    };
    let authentication_data = if authentication_data.is_null() {
        None
    } else {
        Some(authentication_data.to_vec())
    };

    let (symmetric_key, encrypted_header) = wasm_unwrap!(
        EncryptedHeader::generate(
            &CoverCryptX25519Aes256::default(),
            &policy,
            &public_key,
            &access_policy,
            header_metadata.as_deref(),
            authentication_data.as_deref(),
        ),
        "Error encrypting header"
    );
    let symmetric_key_bytes = symmetric_key.into_bytes();
    let encrypted_header_bytes = wasm_unwrap!(
        encrypted_header.try_to_bytes(),
        "Error serializing encrypted header"
    );
    let mut res = Vec::with_capacity(symmetric_key_bytes.len() + encrypted_header_bytes.len());
    res.extend_from_slice(&symmetric_key_bytes);
    res.extend_from_slice(&encrypted_header_bytes);
    Ok(Uint8Array::from(res.as_slice()))
}

// -------------------------------
//         Decryption
// -------------------------------

/// Decrypt with a user decryption key an encrypted header
/// of a resource encrypted using an hybrid crypto scheme.
#[wasm_bindgen]
pub fn webassembly_decrypt_hybrid_header(
    usk_bytes: Uint8Array,
    encrypted_header_bytes: Uint8Array,
    authentication_data: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    //
    // Parse user decryption key
    let usk = wasm_unwrap!(
        UserSecretKey::try_from_bytes(usk_bytes.to_vec().as_slice()),
        "Error deserializing user decryption key"
    );
    let authentication_data = if authentication_data.is_null() {
        None
    } else {
        Some(authentication_data.to_vec())
    };

    //
    // Parse encrypted header
    let encrypted_header = wasm_unwrap!(
        EncryptedHeader::try_from_bytes(encrypted_header_bytes.to_vec().as_slice(),),
        "Error deserializing encrypted header"
    );

    //
    // Finally decrypt symmetric key using given user decryption key
    let cleartext_header = wasm_unwrap!(
        encrypted_header.decrypt(
            &CoverCryptX25519Aes256::default(),
            &usk,
            authentication_data.as_deref(),
        ),
        "Error decrypting header"
    );

    Ok(Uint8Array::from(
        wasm_unwrap!(
            cleartext_header.try_to_bytes(),
            "Error serializing decrypted header"
        )
        .as_slice(),
    ))
}

/// Symmetrically Encrypt plaintext data in a block.
#[wasm_bindgen]
pub fn webassembly_encrypt_symmetric_block(
    symmetric_key_bytes: Uint8Array,
    plaintext_bytes: Uint8Array,
    authentication_data: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    //
    // Check `plaintext_bytes` input parameter
    if plaintext_bytes.length() == 0 {
        return Err(JsValue::from_str("Plaintext value is empty"));
    }

    //
    // Parse symmetric key
    let symmetric_key = wasm_unwrap!(
        <DEM as Dem<{ DEM::KEY_LENGTH }>>::Key::try_from_bytes(&symmetric_key_bytes.to_vec()),
        "Error parsing symmetric key"
    );

    //
    // Encrypt block
    let authentication_data = if authentication_data.is_null() {
        None
    } else {
        Some(authentication_data.to_vec())
    };
    let ciphertext = wasm_unwrap!(
        CoverCryptX25519Aes256::default().encrypt(
            &symmetric_key,
            &plaintext_bytes.to_vec(),
            authentication_data.as_deref(),
        ),
        "Error encrypting block"
    );

    Ok(Uint8Array::from(&ciphertext[..]))
}

/// Symmetrically Decrypt encrypted data in a block.
#[wasm_bindgen]
pub fn webassembly_decrypt_symmetric_block(
    symmetric_key_bytes: Uint8Array,
    encrypted_bytes: Uint8Array,
    authentication_data: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    //
    // Parse symmetric key
    let symmetric_key = wasm_unwrap!(
        <DEM as Dem<{ DEM::KEY_LENGTH }>>::Key::try_from_bytes(&symmetric_key_bytes.to_vec()),
        "Error parsing symmetric key"
    );

    //
    // Decrypt `blockKey<KeyLength>`
    let authentication_data = if authentication_data.is_null() {
        None
    } else {
        Some(authentication_data.to_vec())
    };

    let cleartext = wasm_unwrap!(
        CoverCryptX25519Aes256::default().decrypt(
            &symmetric_key,
            &encrypted_bytes.to_vec(),
            authentication_data.as_deref(),
        ),
        "Error decrypting block"
    );

    Ok(Uint8Array::from(&cleartext[..]))
}

/// Generates both a encrypted header and a DEM encryption of the `plaintext`,
/// with the header metadata as associated data.
///
/// - `metadata_bytes`      : serialized metadata
/// - `policy_bytes`        : serialized policy
/// - `attribute_bytes`     : serialized attributes to use in the encapsulation
/// - `pk`                  : CoverCrypt public key
/// - `plaintext`           : message to encrypt with the DEM
/// - `header_metadata`     : additional data to symmetrically encrypt in the
///   header
/// - `authentication_data` : optional data used for authentication
#[wasm_bindgen]
pub fn webassembly_hybrid_encrypt(
    policy_bytes: Vec<u8>,
    access_policy: String,
    pk: Uint8Array,
    plaintext: Uint8Array,
    header_metadata: Uint8Array,
    authentication_data: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let policy = wasm_unwrap!(
        serde_json::from_slice(&policy_bytes),
        "Error parsing policy"
    );
    let access_policy = wasm_unwrap!(
        AccessPolicy::from_boolean_expression(&access_policy),
        "Error reading access policy"
    );
    let pk = wasm_unwrap!(
        PublicKey::try_from_bytes(&pk.to_vec()),
        "Error parsing public key"
    );
    let header_metadata = if header_metadata.is_null() {
        None
    } else {
        Some(header_metadata.to_vec())
    };

    let authentication_data = if authentication_data.is_null() {
        None
    } else {
        Some(authentication_data.to_vec())
    };

    // instantiate CoverCrypt
    let cover_crypt = CoverCryptX25519Aes256::default();
    let (symmetric_key, encrypted_header) = wasm_unwrap!(
        EncryptedHeader::generate(
            &cover_crypt,
            &policy,
            &pk,
            &access_policy,
            header_metadata.as_deref(),
            authentication_data.as_deref(),
        ),
        "Error encrypting header"
    );

    // encrypt the plaintext
    let ciphertext = wasm_unwrap!(
        cover_crypt.encrypt(
            &symmetric_key,
            &plaintext.to_vec(),
            authentication_data.as_deref(),
        ),
        "Error encrypting symmetric plaintext"
    );

    // concatenate the encrypted header and the ciphertext
    let mut ser = Serializer::with_capacity(encrypted_header.length() + ciphertext.len());
    wasm_unwrap!(
        ser.write(&encrypted_header),
        "Error serializing encrypted header"
    );
    wasm_unwrap!(ser.write_array(&ciphertext), "Error writing ciphertext");
    Ok(Uint8Array::from(ser.finalize().as_slice()))
}

/// Decrypt the DEM ciphertext with the header encapsulated symmetric key,
/// with the header metadata as associated data.
///
/// - `usk_bytes`           : serialized user secret key
/// - `encrypted_bytes`     : concatenation of the encrypted header and the DEM
///   ciphertext
/// - `authentication_data` : optional data used for authentication
///
/// Return the decrypted data (additional data in header and cleartext) as a
/// binary format: 1. LEB128 length of the additional data bytes
/// 2. additional data bytes
/// 3. cleartext bytes
#[wasm_bindgen]
pub fn webassembly_hybrid_decrypt(
    usk_bytes: Uint8Array,
    encrypted_bytes: Uint8Array,
    authentication_data: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    // Read encrypted bytes as the concatenation of an encrypted header and a DEM
    // ciphertext.
    let encrypted_bytes = encrypted_bytes.to_vec();
    let mut de = Deserializer::new(&encrypted_bytes);
    let header = wasm_unwrap!(
        // This will read the exact header size.
        de.read::<EncryptedHeader>(),
        "Error deserializing encrypted header"
    );
    // The rest is the symmetric ciphertext.
    let ciphertext = de.finalize();

    let usk = wasm_unwrap!(
        UserSecretKey::try_from_bytes(usk_bytes.to_vec().as_slice()),
        "Error deserializing user secret key"
    );

    let authentication_data = if authentication_data.is_null() {
        None
    } else {
        Some(authentication_data.to_vec())
    };

    // Instantiate CoverCrypt
    let cover_crypt = CoverCryptX25519Aes256::default();

    // Decrypt header
    let cleartext_header = wasm_unwrap!(
        header.decrypt(&cover_crypt, &usk, authentication_data.as_deref()),
        "Error decrypting header"
    );

    let cleartext = wasm_unwrap!(
        cover_crypt.decrypt(
            &cleartext_header.symmetric_key,
            ciphertext.as_slice(),
            authentication_data.as_deref(),
        ),
        "Error decrypting ciphertext"
    );

    let mut ser = Serializer::new();
    wasm_unwrap!(
        ser.write_vec(cleartext_header.metadata.as_slice()),
        "Cannot serialize the decrypted header metadata into response"
    );
    wasm_unwrap!(
        ser.write_array(cleartext.as_slice()),
        "Cannot serialize the cleartext into response"
    );
    Ok(Uint8Array::from(ser.finalize().as_slice()))
}
