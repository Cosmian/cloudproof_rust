use std::ffi::{CStr, CString};

use cosmian_cover_crypt::{
    abe_policy::{AccessPolicy, Policy},
    test_utils::policy,
    CleartextHeader, Covercrypt, EncryptedHeader, Error, MasterPublicKey, MasterSecretKey,
    UserSecretKey,
};
use cosmian_crypto_core::{bytes_ser_de::Serializable, Aes256Gcm, FixedSizeCBytes, SymmetricKey};
use cosmian_ffi_utils::error::h_get_error;

use crate::ffi::{
    generate_cc_keys::{h_generate_master_keys, h_generate_user_secret_key},
    hybrid_cc_aes::{
        h_create_decryption_cache, h_create_encryption_cache, h_decrypt_header,
        h_decrypt_header_using_cache, h_destroy_decryption_cache, h_destroy_encryption_cache,
        h_encrypt_header, h_encrypt_header_using_cache, h_hybrid_decrypt, h_hybrid_encrypt,
    },
};

unsafe fn encrypt_header(
    policy: &Policy,
    encryption_policy: &str,
    public_key: &MasterPublicKey,
    header_metadata: &[u8],
    authentication_data: &[u8],
) -> (SymmetricKey<{ Aes256Gcm::KEY_LENGTH }>, EncryptedHeader) {
    let mut symmetric_key = vec![0u8; 32];
    let mut symmetric_key_ptr = symmetric_key.as_mut_ptr().cast();
    let mut symmetric_key_len = symmetric_key.len() as i32;

    let mut encrypted_header_bytes = vec![0u8; 8128];
    let mut encrypted_header_ptr = encrypted_header_bytes.as_mut_ptr().cast();
    let mut encrypted_header_len = encrypted_header_bytes.len() as i32;

    let policy_bytes: Vec<u8> = policy.try_into().unwrap();
    let policy_ptr = policy_bytes.as_ptr().cast();
    let policy_len = policy_bytes.len() as i32;

    let public_key_bytes = public_key.serialize().unwrap();
    let public_key_ptr = public_key_bytes.as_ptr();
    let public_key_len = public_key_bytes.len() as i32;

    let encryption_policy_cs = CString::new(encryption_policy).unwrap();
    let encryption_policy_ptr = encryption_policy_cs.as_ptr();

    let res = h_encrypt_header(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        encrypted_header_ptr,
        &mut encrypted_header_len,
        policy_ptr,
        policy_len,
        public_key_ptr.cast(),
        public_key_len,
        encryption_policy_ptr,
        header_metadata.as_ptr().cast(),
        header_metadata.len() as i32,
        authentication_data.as_ptr().cast(),
        authentication_data.len() as i32,
    );

    if 0 != res {
        symmetric_key = vec![0u8; symmetric_key_len as usize];
        encrypted_header_bytes = vec![0u8; encrypted_header_len as usize];
        symmetric_key_ptr = symmetric_key.as_mut_ptr().cast();
        encrypted_header_ptr = encrypted_header_bytes.as_mut_ptr().cast();
        unwrap_ffi_error(h_encrypt_header(
            symmetric_key_ptr,
            &mut symmetric_key_len,
            encrypted_header_ptr,
            &mut encrypted_header_len,
            policy_ptr,
            policy_len,
            public_key_ptr.cast(),
            public_key_len,
            encryption_policy_ptr,
            header_metadata.as_ptr().cast(),
            header_metadata.len() as i32,
            authentication_data.as_ptr().cast(),
            authentication_data.len() as i32,
        ));
    }

    let symmetric_key_fixed_length =
        std::slice::from_raw_parts(symmetric_key_ptr.cast(), symmetric_key_len as usize)
            .try_into()
            .unwrap();
    let symmetric_key = SymmetricKey::try_from_bytes(symmetric_key_fixed_length).unwrap();

    let encrypted_header_bytes_ =
        std::slice::from_raw_parts(encrypted_header_ptr.cast(), encrypted_header_len as usize)
            .to_vec();
    (
        symmetric_key,
        EncryptedHeader::deserialize(&encrypted_header_bytes_).unwrap(),
    )
}

unsafe fn decrypt_header(
    header: &EncryptedHeader,
    user_decryption_key: &UserSecretKey,
    authentication_data: &[u8],
) -> CleartextHeader {
    let mut symmetric_key = vec![0u8; 32];
    let mut symmetric_key_ptr = symmetric_key.as_mut_ptr().cast();
    let mut symmetric_key_len = symmetric_key.len() as i32;

    let mut header_metadata = vec![0u8; 32];
    let mut header_metadata_ptr = header_metadata.as_mut_ptr().cast();
    let mut header_metadata_len = header_metadata.len() as i32;

    let header_bytes = header.serialize().unwrap();

    let authentication_data_ptr = authentication_data.as_ptr().cast();
    let authentication_data_len = authentication_data.len() as i32;

    let user_decryption_key_bytes = user_decryption_key.serialize().unwrap();
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    let res = h_decrypt_header(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        header_metadata_ptr,
        &mut header_metadata_len,
        header_bytes.as_ptr().cast(),
        header_bytes.len() as i32,
        authentication_data_ptr,
        authentication_data_len,
        user_decryption_key_ptr,
        user_decryption_key_len,
    );

    if 0 != res {
        symmetric_key = vec![0u8; symmetric_key_len as usize];
        header_metadata = vec![0u8; header_metadata_len as usize];
        symmetric_key_ptr = symmetric_key.as_mut_ptr().cast();
        header_metadata_ptr = header_metadata.as_mut_ptr().cast();
        unwrap_ffi_error(h_decrypt_header(
            symmetric_key_ptr,
            &mut symmetric_key_len,
            header_metadata_ptr,
            &mut header_metadata_len,
            header_bytes.as_ptr().cast(),
            header_bytes.len() as i32,
            authentication_data_ptr,
            authentication_data_len,
            user_decryption_key_ptr,
            user_decryption_key_len,
        ));
    }

    let symmetric_key_fixed_length =
        std::slice::from_raw_parts(symmetric_key_ptr.cast(), symmetric_key_len as usize)
            .try_into()
            .unwrap();
    let symmetric_key = SymmetricKey::try_from_bytes(symmetric_key_fixed_length).unwrap();

    let header_metadata =
        std::slice::from_raw_parts(header_metadata_ptr.cast(), header_metadata_len as usize)
            .to_vec();

    CleartextHeader {
        symmetric_key,
        metadata: Some(header_metadata),
    }
}

unsafe fn unwrap_ffi_error(val: i32) {
    if val != 0 {
        let mut message_bytes_key = vec![0u8; 8128];
        let message_bytes_ptr = message_bytes_key.as_mut_ptr().cast();
        let mut message_bytes_len = message_bytes_key.len() as i32;
        h_get_error(message_bytes_ptr, &mut message_bytes_len);
        let cstr = CStr::from_ptr(message_bytes_ptr);
        let msg = cstr.to_str().unwrap();
        panic!("{msg}");
    }
}

#[test]
fn test_ffi_hybrid_header() -> Result<(), Error> {
    unsafe {
        //
        // Policy settings
        //
        let policy = policy().unwrap();
        let encryption_policy = "(Department::HR || Department::FIN) && Security Level::Low Secret";

        //
        // CoverCrypt setup
        //
        let cover_crypt = Covercrypt::default();
        let (msk, mpk) = cover_crypt.generate_master_keys(&policy).unwrap();
        let user_access_policy =
            AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Top Secret")
                .unwrap();
        let usk = cover_crypt
            .generate_user_secret_key(&msk, &user_access_policy, &policy)
            .unwrap();

        //
        // Encrypt / decrypt
        //
        let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let authentication_data = vec![10, 11, 12, 13, 14];

        let (sym_key, encrypted_header) = encrypt_header(
            &policy,
            encryption_policy,
            &mpk,
            &header_metadata,
            &authentication_data,
        );

        let decrypted_header = decrypt_header(&encrypted_header, &usk, &authentication_data);

        assert_eq!(sym_key, decrypted_header.symmetric_key);
        assert_eq!(&header_metadata, &decrypted_header.metadata.unwrap());
    }
    Ok(())
}

unsafe fn encrypt_header_using_cache(
    public_key: &MasterPublicKey,
    policy: &Policy,
    header_metadata: &[u8],
    authentication_data: &[u8],
) -> (SymmetricKey<{ Aes256Gcm::KEY_LENGTH }>, EncryptedHeader) {
    let policy_bytes: Vec<u8> = policy.try_into().unwrap();
    let policy_ptr = policy_bytes.as_ptr().cast();
    let policy_len = policy_bytes.len() as i32;

    let public_key_bytes = public_key.serialize().unwrap();
    let public_key_ptr = public_key_bytes.as_ptr().cast();
    let public_key_len = public_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;

    unwrap_ffi_error(h_create_encryption_cache(
        &mut cache_handle,
        policy_ptr,
        policy_len,
        public_key_ptr,
        public_key_len,
    ));

    let encryption_policy = "Department::FIN && Security Level::Low Secret";

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast();
    let mut symmetric_key_len = symmetric_key.len() as i32;

    let mut encrypted_header_bytes = vec![0u8; 8128];
    let encrypted_header_ptr = encrypted_header_bytes.as_mut_ptr().cast();
    let mut encrypted_header_len = encrypted_header_bytes.len() as i32;

    let encryption_policy_cs = CString::new(encryption_policy).unwrap();

    unwrap_ffi_error(h_encrypt_header_using_cache(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        encrypted_header_ptr,
        &mut encrypted_header_len,
        cache_handle,
        encryption_policy_cs.as_ptr(),
        header_metadata.as_ptr().cast(),
        header_metadata.len() as i32,
        authentication_data.as_ptr().cast(),
        authentication_data.len() as i32,
    ));

    let symmetric_key_fixed_length =
        std::slice::from_raw_parts(symmetric_key_ptr.cast(), symmetric_key_len as usize)
            .try_into()
            .unwrap();
    let symmetric_key = SymmetricKey::try_from_bytes(symmetric_key_fixed_length).unwrap();

    let encrypted_header_bytes_ =
        std::slice::from_raw_parts(encrypted_header_ptr.cast(), encrypted_header_len as usize)
            .to_vec();

    unwrap_ffi_error(h_destroy_encryption_cache(cache_handle));

    (
        symmetric_key,
        EncryptedHeader::deserialize(&encrypted_header_bytes_).unwrap(),
    )
}

unsafe fn decrypt_header_using_cache(
    user_decryption_key: &UserSecretKey,
    header: &EncryptedHeader,
    authentication_data: &[u8],
) -> CleartextHeader {
    let user_decryption_key_bytes = user_decryption_key.serialize().unwrap();
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;

    unwrap_ffi_error(h_create_decryption_cache(
        &mut cache_handle,
        user_decryption_key_ptr,
        user_decryption_key_len,
    ));

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast();
    let mut symmetric_key_len = symmetric_key.len() as i32;

    let mut header_metadata = vec![0u8; 8128];
    let header_metadata_ptr = header_metadata.as_mut_ptr().cast();
    let mut header_metadata_len = header_metadata.len() as i32;

    let header_bytes = header.serialize().unwrap();

    unwrap_ffi_error(h_decrypt_header_using_cache(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        header_metadata_ptr,
        &mut header_metadata_len,
        header_bytes.as_ptr().cast(),
        header_bytes.len() as i32,
        authentication_data.as_ptr().cast(),
        authentication_data.len() as i32,
        cache_handle,
    ));

    let symmetric_key_fixed_length =
        std::slice::from_raw_parts(symmetric_key_ptr.cast(), symmetric_key_len as usize)
            .try_into()
            .unwrap();
    let symmetric_key = SymmetricKey::try_from_bytes(symmetric_key_fixed_length).unwrap();

    let header_metadata =
        std::slice::from_raw_parts(header_metadata_ptr.cast(), header_metadata_len as usize)
            .to_vec();

    unwrap_ffi_error(h_destroy_decryption_cache(cache_handle));

    CleartextHeader {
        symmetric_key,
        metadata: Some(header_metadata),
    }
}

#[test]
fn test_ffi_hybrid_header_using_cache() {
    unsafe {
        let policy = policy().unwrap();

        //
        // CoverCrypt setup
        //
        let cover_crypt = Covercrypt::default();
        let (msk, mpk) = cover_crypt.generate_master_keys(&policy).unwrap();
        let access_policy = AccessPolicy::new("Department", "FIN")
            & AccessPolicy::new("Security Level", "Top Secret");
        let sk_u = cover_crypt
            .generate_user_secret_key(&msk, &access_policy, &policy)
            .unwrap();

        //
        // Encrypt / decrypt
        //
        let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let authentication_data = vec![10, 11, 12, 13, 14];

        let (symmetric_key, encrypted_header) =
            encrypt_header_using_cache(&mpk, &policy, &header_metadata, &authentication_data);
        let decrypted_header =
            decrypt_header_using_cache(&sk_u, &encrypted_header, &authentication_data);

        assert_eq!(symmetric_key, decrypted_header.symmetric_key);
        assert_eq!(&header_metadata, &decrypted_header.metadata.unwrap());
    }
}

unsafe fn generate_master_keys(policy: &Policy) -> (MasterSecretKey, MasterPublicKey) {
    let policy_bytes: Vec<u8> = policy.try_into().unwrap();
    let policy_ptr = policy_bytes.as_ptr().cast();
    let policy_len = policy_bytes.len() as i32;

    // use a large enough buffer size
    let mut msk_bytes = vec![0u8; 8 * 1024];
    let msk_ptr = msk_bytes.as_mut_ptr().cast();
    let mut msk_len = msk_bytes.len() as i32;

    // use a large enough buffer size
    let mut mpk_bytes = vec![0u8; 8 * 1024];
    let mpk_ptr = mpk_bytes.as_mut_ptr().cast();
    let mut mpk_len = mpk_bytes.len() as i32;

    unwrap_ffi_error(h_generate_master_keys(
        msk_ptr,
        &mut msk_len,
        mpk_ptr,
        &mut mpk_len,
        policy_ptr,
        policy_len,
    ));

    let msk_bytes = std::slice::from_raw_parts(msk_ptr.cast(), msk_len as usize);
    let mpk_bytes = std::slice::from_raw_parts(mpk_ptr.cast(), mpk_len as usize);

    let msk = MasterSecretKey::deserialize(msk_bytes).unwrap();
    let mpk = MasterPublicKey::deserialize(mpk_bytes).unwrap();

    (msk, mpk)
}

unsafe fn generate_user_secret_key(
    msk: &MasterSecretKey,
    access_policy: &str,
    policy: &Policy,
) -> UserSecretKey {
    //
    // Prepare secret key
    let msk_bytes = msk.serialize().unwrap();
    let msk_ptr = msk_bytes.as_ptr().cast();
    let msk_len = msk_bytes.len() as i32;

    //
    // Get pointer from access policy
    let access_policy_cs = CString::new(access_policy).unwrap();
    let access_policy_ptr = access_policy_cs.as_ptr();
    //
    // Get pointer from policy
    let policy_bytes: Vec<u8> = policy.try_into().unwrap();
    let policy_ptr = policy_bytes.as_ptr().cast();
    let policy_len = policy_bytes.len() as i32;

    // Prepare OUT buffer
    // use a large enough buffer size
    let mut usk_bytes = vec![0u8; 37696];
    let usk_ptr = usk_bytes.as_mut_ptr().cast();
    let mut usk_len = usk_bytes.len() as i32;

    unwrap_ffi_error(h_generate_user_secret_key(
        usk_ptr,
        &mut usk_len,
        msk_ptr,
        msk_len,
        access_policy_ptr,
        policy_ptr,
        policy_len,
    ));

    let user_key_bytes = std::slice::from_raw_parts(usk_ptr.cast(), usk_len as usize).to_vec();

    UserSecretKey::deserialize(&user_key_bytes).unwrap()
}

#[test]
fn test_ffi_keygen() {
    //
    // Policy settings
    let policy = policy().unwrap();

    //
    // Generate master keys
    let master_keys = unsafe { generate_master_keys(&policy) };

    //
    // Set an access policy
    let access_policy = "Department::FIN && Security Level::Top Secret";

    //
    // Generate user secret key
    let _usk = unsafe { generate_user_secret_key(&master_keys.0, access_policy, &policy) };
}

//
// Encrypt / decrypt
//

unsafe fn encrypt(
    policy: &Policy,
    public_key: &MasterPublicKey,
    encryption_policy: &str,
    plaintext: &[u8],
    header_metadata: &[u8],
    authentication_data: &[u8],
) -> Vec<u8> {
    let mut ciphertext_bytes = vec![0u8; 8128];
    let ciphertext_ptr = ciphertext_bytes.as_mut_ptr().cast();
    let mut ciphertext_len = ciphertext_bytes.len() as i32;

    let policy_bytes: Vec<u8> = policy.try_into().unwrap();
    let policy_ptr = policy_bytes.as_ptr().cast();
    let policy_len = policy_bytes.len() as i32;

    let public_key_bytes = public_key.serialize().unwrap();
    let public_key_ptr = public_key_bytes.as_ptr();
    let public_key_len = public_key_bytes.len() as i32;

    let encryption_policy_cs = CString::new(encryption_policy).unwrap();
    let encryption_policy_ptr = encryption_policy_cs.as_ptr();

    unwrap_ffi_error(h_hybrid_encrypt(
        ciphertext_ptr,
        &mut ciphertext_len,
        policy_ptr,
        policy_len,
        public_key_ptr.cast(),
        public_key_len,
        encryption_policy_ptr,
        plaintext.as_ptr().cast(),
        plaintext.len() as i32,
        header_metadata.as_ptr().cast(),
        header_metadata.len() as i32,
        authentication_data.as_ptr().cast(),
        authentication_data.len() as i32,
    ));

    let ciphertext_bytes =
        std::slice::from_raw_parts(ciphertext_ptr.cast(), ciphertext_len as usize).to_vec();
    ciphertext_bytes
}

unsafe fn decrypt(
    ciphertext: &[u8],
    user_decryption_key: &UserSecretKey,
    authentication_data: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    // use a large enough buffer size
    let mut plaintext = vec![0u8; 8192];
    let plaintext_ptr = plaintext.as_mut_ptr().cast();
    let mut plaintext_len = plaintext.len() as i32;

    // use a large enough buffer size
    let mut metadata = vec![0u8; 8192];
    let metadata_ptr = metadata.as_mut_ptr().cast();
    let mut metadata_len = metadata.len() as i32;

    let ciphertext_ptr = ciphertext.as_ptr().cast();
    let ciphertext_len = ciphertext.len() as i32;

    let authentication_data_ptr = authentication_data.as_ptr().cast();
    let authentication_data_len = authentication_data.len() as i32;

    let user_decryption_key_bytes = user_decryption_key.serialize().unwrap();
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    unwrap_ffi_error(h_hybrid_decrypt(
        plaintext_ptr,
        &mut plaintext_len,
        metadata_ptr,
        &mut metadata_len,
        ciphertext_ptr,
        ciphertext_len,
        authentication_data_ptr,
        authentication_data_len,
        user_decryption_key_ptr,
        user_decryption_key_len,
    ));

    let plaintext =
        std::slice::from_raw_parts(plaintext_ptr.cast(), plaintext_len as usize).to_vec();
    let header_metadata =
        std::slice::from_raw_parts(metadata_ptr.cast(), metadata_len as usize).to_vec();

    (plaintext, header_metadata)
}

#[test]
fn test_encrypt_decrypt() {
    unsafe {
        //
        // Policy settings
        //
        let policy = policy().unwrap();
        let encryption_policy = "(Department::HR || Department::FIN) && Security Level::Low Secret";

        //
        // CoverCrypt setup
        //
        let cover_crypt = Covercrypt::default();
        let (msk, mpk) = cover_crypt.generate_master_keys(&policy).unwrap();
        let user_access_policy =
            AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Top Secret")
                .unwrap();
        let usk = cover_crypt
            .generate_user_secret_key(&msk, &user_access_policy, &policy)
            .unwrap();

        //
        // Encrypt / decrypt
        //
        let plaintext = vec![16, 17, 18, 19, 20, 21];
        let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let authentication_data = vec![10, 11, 12, 13, 14];

        let ciphertext = encrypt(
            &policy,
            &mpk,
            encryption_policy,
            &plaintext,
            &header_metadata,
            &authentication_data,
        );

        let (plaintext_, header_metadata_) = decrypt(&ciphertext, &usk, &authentication_data);

        assert_eq!(plaintext, plaintext_);
        assert_eq!(header_metadata, header_metadata_);
    }
}
