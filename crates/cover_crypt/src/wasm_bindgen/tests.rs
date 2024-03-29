use cosmian_cover_crypt::{
    abe_policy::Policy, core::SYM_KEY_LENGTH, test_utils::policy, CleartextHeader, EncryptedHeader,
    MasterPublicKey, MasterSecretKey, UserSecretKey,
};
use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable};
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

use crate::wasm_bindgen::{
    abe_policy::webassembly_rename_attribute,
    generate_cc_keys::{webassembly_generate_master_keys, webassembly_generate_user_secret_key},
    hybrid_cc_aes::{
        webassembly_decrypt_hybrid_header, webassembly_encrypt_hybrid_header,
        webassembly_hybrid_decrypt, webassembly_hybrid_encrypt, webassembly_split_encrypted_header,
    },
};

fn encrypt_header(
    policy: &Policy,
    access_policy_string: String,
    public_key: &MasterPublicKey,
    header_metadata: &[u8],
    authentication_data: &[u8],
) -> Result<EncryptedHeader, JsValue> {
    let header_metadata = Uint8Array::from(header_metadata);
    let authentication_data = Uint8Array::from(authentication_data);
    let policy_bytes = wasm_unwrap!(policy.try_into(), "Error serializing policy");
    let public_key_bytes = Uint8Array::from(
        wasm_unwrap!(public_key.serialize(), "Error serializing public key").as_slice(),
    );
    let encrypted_header = wasm_unwrap!(
        webassembly_encrypt_hybrid_header(
            policy_bytes,
            access_policy_string,
            public_key_bytes,
            header_metadata,
            authentication_data,
        ),
        "Error encrypting header"
    );
    EncryptedHeader::deserialize(&encrypted_header.to_vec()[SYM_KEY_LENGTH..])
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

fn decrypt_header(
    encrypted_header: &EncryptedHeader,
    user_decryption_key: &UserSecretKey,
    authentication_data: &[u8],
) -> Result<CleartextHeader, JsValue> {
    let authentication_data = Uint8Array::from(authentication_data);
    let encrypted_header_bytes = Uint8Array::from(
        wasm_unwrap!(
            encrypted_header.serialize(),
            "Error serializing encrypted header"
        )
        .as_slice(),
    );
    let sk_u = Uint8Array::from(
        wasm_unwrap!(
            user_decryption_key.serialize(),
            "Error serializing the user secret key"
        )
        .as_slice(),
    );
    let decrypted_header_bytes = wasm_unwrap!(
        webassembly_decrypt_hybrid_header(sk_u, encrypted_header_bytes, authentication_data),
        "Error decrypting header"
    );
    CleartextHeader::deserialize(&decrypted_header_bytes.to_vec())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt() {
    //
    // Policy settings
    //
    let policy = policy().unwrap();
    let access_policy_string = "Department::FIN && Security Level::Top Secret";

    //
    // CoverCrypt setup
    //

    let policy_bytes = serde_json::to_vec(&policy).unwrap();
    let master_keys = webassembly_generate_master_keys(policy_bytes.clone())
        .unwrap()
        .to_vec();
    let msk_len = u32::from_be_bytes(<[u8; 4]>::try_from(&master_keys[..4]).unwrap()) as usize;
    let usk = webassembly_generate_user_secret_key(
        Uint8Array::from(&master_keys[4..msk_len + 4]),
        access_policy_string,
        policy_bytes.clone(),
    )
    .unwrap()
    .to_vec();

    //
    // Encrypt / decrypt
    //
    let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let authentication_data = vec![10, 11, 12, 13, 14];

    let plaintext = "My secret message!";

    let res = webassembly_hybrid_encrypt(
        policy_bytes,
        access_policy_string.to_string(),
        Uint8Array::from(&master_keys[4 + msk_len..]),
        Uint8Array::from(plaintext.as_bytes()),
        Uint8Array::from(header_metadata.as_slice()),
        Uint8Array::from(authentication_data.as_slice()),
    )
    .unwrap();

    // try decryption by first split encrypted header and ciphertext
    {
        // split
        let split = webassembly_split_encrypted_header(res.clone()).unwrap();
        let obj = split.dyn_ref::<Object>().unwrap();
        let mut enc_header =
            Uint8Array::from(Reflect::get(obj, &JsValue::from_str("encryptedHeader")).unwrap())
                .to_vec();
        let mut ciphertext =
            Uint8Array::from(Reflect::get(obj, &JsValue::from_str("ciphertext")).unwrap()).to_vec();

        // reconcatenate
        enc_header.append(&mut ciphertext);

        // decryption should still work
        let res = webassembly_hybrid_decrypt(
            Uint8Array::from(usk.as_slice()),
            Uint8Array::from(enc_header.as_slice()),
            Uint8Array::from(authentication_data.as_slice()),
        )
        .unwrap()
        .to_vec();

        let mut de = Deserializer::new(res.as_slice());
        let decrypted_header_metadata = de.read_vec().unwrap();
        let decrypted_plaintext = de.finalize();

        assert_eq!(plaintext.as_bytes(), decrypted_plaintext);
        assert_eq!(header_metadata, decrypted_header_metadata);
    }

    let res = webassembly_hybrid_decrypt(
        Uint8Array::from(usk.as_slice()),
        res,
        Uint8Array::from(authentication_data.as_slice()),
    )
    .unwrap()
    .to_vec();

    let mut de = Deserializer::new(res.as_slice());
    let decrypted_header_metadata = de.read_vec().unwrap();
    let decrypted_plaintext = de.finalize();

    assert_eq!(plaintext.as_bytes(), decrypted_plaintext);
    assert_eq!(header_metadata, decrypted_header_metadata);
}

#[wasm_bindgen_test]
fn test_generate_keys() {
    //
    // Policy settings
    //
    let policy = policy().unwrap();
    let policy_bytes = serde_json::to_vec(&policy).unwrap();

    //
    // Generate master keys
    let master_keys = webassembly_generate_master_keys(policy_bytes.clone()).unwrap();
    let master_keys_vec = master_keys.to_vec();
    let msk_size = u32::from_be_bytes(master_keys_vec[0..4].try_into().unwrap()) as usize;
    let msk_bytes = &master_keys_vec[4..4 + msk_size];

    //
    // Check deserialization
    MasterSecretKey::deserialize(msk_bytes).unwrap();
    MasterPublicKey::deserialize(&master_keys_vec[4 + msk_size..]).unwrap();

    //
    // Generate user secret key
    let usk_bytes = webassembly_generate_user_secret_key(
        Uint8Array::from(msk_bytes),
        "Department::FIN && Security Level::Top Secret",
        policy_bytes.clone(),
    )
    .unwrap()
    .to_vec();
    let usk = UserSecretKey::deserialize(&usk_bytes).unwrap();

    //
    // Rename attribute `Department::FIN` -> `Department::Finance`
    let new_policy_bytes = webassembly_rename_attribute(
        policy_bytes.clone(),
        "Department::FIN".to_string(),
        "Finance".to_string(),
    )
    .unwrap();
    let new_policy = serde_json::from_slice(&new_policy_bytes).unwrap();

    //
    // Generate master keys
    let master_keys = webassembly_generate_master_keys(new_policy_bytes.clone()).unwrap();
    let master_keys_vec = master_keys.to_vec();
    let secret_key_size = u32::from_be_bytes(master_keys_vec[..4].try_into().unwrap()) as usize;
    let secret_key_bytes = &master_keys_vec[4..4 + secret_key_size];
    MasterSecretKey::deserialize(secret_key_bytes).unwrap();
    let master_public_key =
        MasterPublicKey::deserialize(&master_keys_vec[4 + secret_key_size..]).unwrap();

    //
    // Encrypt / decrypt
    //

    let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let authentication_data = vec![10, 11, 12, 13, 14];

    let encrypted_header = encrypt_header(
        &new_policy,
        "Department::Finance && Security Level::Low Secret".to_string(),
        &master_public_key,
        &header_metadata,
        &authentication_data,
    )
    .unwrap();

    //
    // Try to decrypt with a non-refreshed secret key (it fails)
    //
    assert!(decrypt_header(&encrypted_header, &usk, &authentication_data).is_err());

    //
    // Refresh user secret key
    let usk_bytes = webassembly_generate_user_secret_key(
        Uint8Array::from(secret_key_bytes),
        "Security Level::Low Secret",
        new_policy_bytes,
    )
    .unwrap()
    .to_vec();
    let usk = UserSecretKey::deserialize(&usk_bytes).unwrap();

    //
    // Decrypt with the refreshed secret key (it now works)
    //
    decrypt_header(&encrypted_header, &usk, &authentication_data).unwrap();
}
