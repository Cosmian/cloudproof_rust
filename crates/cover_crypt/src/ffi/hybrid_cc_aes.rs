use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicI32, Ordering},
        RwLock,
    },
};

use cosmian_cover_crypt::{
    abe_policy::{AccessPolicy, Policy},
    Covercrypt, EncryptedHeader, MasterPublicKey, UserSecretKey,
};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    Aes256Gcm, FixedSizeCBytes, SymmetricKey,
};
use cosmian_ffi_utils::{
    ffi_bail, ffi_read_bytes, ffi_read_string, ffi_unwrap, ffi_write_bytes, ErrorCode,
};
use lazy_static::lazy_static;

// -------------------------------
//         Encryption
// -------------------------------

// A static cache of the Encryption Caches
lazy_static! {
    static ref ENCRYPTION_CACHE_MAP: RwLock<HashMap<i32, EncryptionCache>> =
        RwLock::new(HashMap::new());
    static ref NEXT_ENCRYPTION_CACHE_ID: std::sync::atomic::AtomicI32 = AtomicI32::new(0);
}

/// An Encryption Cache that will be used to cache Rust side
/// the Public Key and the Policy when doing multiple serial encryptions
pub struct EncryptionCache {
    policy: Policy,
    mpk: MasterPublicKey,
}

#[no_mangle]
/// Creates a cache containing the Public Key and Policy. This cache can be
/// reused when encrypting messages which avoids passing these objects to Rust
/// in each call.
///
/// WARNING: [`h_destroy_encrypt_cache()`](h_destroy_encryption_cache)
/// should be called to reclaim the cache memory.
///
/// # Safety
pub unsafe extern "C" fn h_create_encryption_cache(
    cache_handle: *mut i32,
    policy_ptr: *const i8,
    policy_len: i32,
    mpk_ptr: *const i8,
    mpk_len: i32,
) -> i32 {
    let policy = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy = ffi_unwrap!(
        Policy::try_from(policy),
        "error deserializing policy",
        ErrorCode::Serialization
    );
    let mpk = ffi_read_bytes!("public key", mpk_ptr, mpk_len);
    let mpk = ffi_unwrap!(
        MasterPublicKey::deserialize(mpk),
        "error deserializing public key",
        ErrorCode::Serialization
    );

    let cache = EncryptionCache { policy, mpk };
    let id = NEXT_ENCRYPTION_CACHE_ID.fetch_add(1, Ordering::Acquire);
    let mut map = ENCRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on encryption cache failed");
    map.insert(id, cache);
    *cache_handle = id;

    0
}

#[no_mangle]
/// Reclaims the memory of the cache.
///
/// Cf [`h_create_encrypt_cache()`](h_create_encryption_cache).
///
/// # Safety
pub unsafe extern "C" fn h_destroy_encryption_cache(cache_handle: i32) -> i32 {
    let mut map = ENCRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on encryption cache failed");
    map.remove(&cache_handle);
    0
}

#[no_mangle]
/// Encrypts a header using an encryption cache.
///
/// # Safety
pub unsafe extern "C" fn h_encrypt_header_using_cache(
    symmetric_key_ptr: *mut i8,
    symmetric_key_len: *mut i32,
    header_bytes_ptr: *mut i8,
    header_bytes_len: *mut i32,
    cache_handle: i32,
    encryption_policy_ptr: *const i8,
    header_metadata_ptr: *const i8,
    header_metadata_len: i32,
    authentication_data_ptr: *const i8,
    authentication_data_len: i32,
) -> i32 {
    let encryption_policy_bytes = ffi_read_string!("encryption policy", encryption_policy_ptr);
    let encryption_policy = ffi_unwrap!(
        AccessPolicy::from_boolean_expression(&encryption_policy_bytes),
        "error parsing encryption policy",
        ErrorCode::CovercryptPolicy
    );

    let header_metadata = if header_metadata_ptr.is_null() || header_metadata_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "header metadata",
            header_metadata_ptr,
            header_metadata_len
        ))
    };

    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let map = ENCRYPTION_CACHE_MAP
        .read()
        .expect("a read mutex on the encryption cache failed");
    let cache = if let Some(cache) = map.get(&cache_handle) {
        cache
    } else {
        ffi_bail!(format!(
            "Hybrid Cipher: no encryption cache with handle: {cache_handle}"
        ));
    };

    let (symmetric_key, encrypted_header) = ffi_unwrap!(
        EncryptedHeader::generate(
            &Covercrypt::default(),
            &cache.policy,
            &cache.mpk,
            &encryption_policy,
            header_metadata,
            authentication_data,
        ),
        "error encrypting CoverCrypt header",
        ErrorCode::Covercrypt
    );

    let encrypted_header_bytes = ffi_unwrap!(
        encrypted_header.serialize(),
        "error serializing encrypted CoverCrypt header",
        ErrorCode::Serialization
    );

    ffi_write_bytes!(
        "symmetric key",
        &symmetric_key,
        symmetric_key_ptr,
        symmetric_key_len,
        "encrypted header",
        &encrypted_header_bytes,
        header_bytes_ptr,
        header_bytes_len
    );
}

#[no_mangle]
/// Encrypts a header without using an encryption cache.
/// It is slower but does not require destroying any cache when done.
///
/// The symmetric key and header bytes are returned in the first OUT parameters
/// # Safety
pub unsafe extern "C" fn h_encrypt_header(
    symmetric_key_ptr: *mut i8,
    symmetric_key_len: *mut i32,
    header_bytes_ptr: *mut i8,
    header_bytes_len: *mut i32,
    policy_ptr: *const i8,
    policy_len: i32,
    mpk_ptr: *const i8,
    mpk_len: i32,
    encryption_policy_ptr: *const i8,
    header_metadata_ptr: *const i8,
    header_metadata_len: i32,
    authentication_data_ptr: *const i8,
    authentication_data_len: i32,
) -> i32 {
    let policy = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy = ffi_unwrap!(
        Policy::try_from(policy),
        "error deserializing policy",
        ErrorCode::Serialization
    );
    let mpk = ffi_read_bytes!("public key", mpk_ptr, mpk_len);
    let mpk = ffi_unwrap!(
        MasterPublicKey::deserialize(mpk),
        "error deserializing public key",
        ErrorCode::Serialization
    );
    let encryption_policy_string = ffi_read_string!("encryption policy", encryption_policy_ptr);
    let encryption_policy = ffi_unwrap!(
        AccessPolicy::from_boolean_expression(&encryption_policy_string),
        "error parsing encryption policy",
        ErrorCode::CovercryptPolicy
    );
    let header_metadata = if header_metadata_ptr.is_null() || header_metadata_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "header metadata",
            header_metadata_ptr,
            header_metadata_len
        ))
    };

    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let (symmetric_key, encrypted_header) = ffi_unwrap!(
        EncryptedHeader::generate(
            &Covercrypt::default(),
            &policy,
            &mpk,
            &encryption_policy,
            header_metadata,
            authentication_data
        ),
        "error encrypting CoverCrypt header",
        ErrorCode::Encryption
    );

    let encrypted_header_bytes = ffi_unwrap!(
        encrypted_header.serialize(),
        "error serializing encrypted CoverCrypt header",
        ErrorCode::Serialization
    );

    ffi_write_bytes!(
        "symmetric key",
        &symmetric_key,
        symmetric_key_ptr,
        symmetric_key_len,
        "encrypted header",
        &encrypted_header_bytes,
        header_bytes_ptr,
        header_bytes_len
    );
}

// -------------------------------
//         Decryption
// -------------------------------

// A cache of the decryption caches
lazy_static! {
    static ref DECRYPTION_CACHE_MAP: RwLock<HashMap<i32, DecryptionCache>> =
        RwLock::new(HashMap::new());
    static ref NEXT_DECRYPTION_CACHE_ID: std::sync::atomic::AtomicI32 = AtomicI32::new(0);
}

/// Cache used to store the user secret key on the Rust side.
pub struct DecryptionCache {
    usk: UserSecretKey,
}

#[no_mangle]
/// Creates a cache containing the user secret key. This cache can be reused
/// when decrypting messages which avoids passing this key to Rust in each call.
///
/// Cf [`h_decrypt_header_using_cache()`](h_decrypt_header_using_cache).
///
/// WARNING: [`h_destroy_decryption_cache()`](h_destroy_decryption_cache)
/// should be called to reclaim the cache memory.
///
/// # Safety
pub unsafe extern "C" fn h_create_decryption_cache(
    cache_handle: *mut i32,
    usk_ptr: *const i8,
    usk_len: i32,
) -> i32 {
    let usk_bytes = ffi_read_bytes!("user secret key", usk_ptr, usk_len);
    let usk = ffi_unwrap!(
        UserSecretKey::deserialize(usk_bytes),
        "error deserializing user secret key",
        ErrorCode::Serialization
    );

    let cache = DecryptionCache { usk };
    let id = NEXT_DECRYPTION_CACHE_ID.fetch_add(1, Ordering::Acquire);
    let mut map = DECRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on decryption cache failed");
    map.insert(id, cache);
    *cache_handle = id;

    0
}

#[no_mangle]
/// Reclaims decryption cache memory.
///
/// # Safety
pub unsafe extern "C" fn h_destroy_decryption_cache(cache_handle: i32) -> i32 {
    let mut map = DECRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on decryption cache failed");
    map.remove(&cache_handle);
    0
}

#[no_mangle]
/// Decrypts an encrypted header using a cache. Returns the symmetric key and
/// header metadata if any.
///
/// No header metadata is returned if `header_metadata_ptr` is `NULL`.
///
/// # Safety
pub unsafe extern "C" fn h_decrypt_header_using_cache(
    symmetric_key_ptr: *mut i8,
    symmetric_key_len: *mut i32,
    header_metadata_ptr: *mut i8,
    header_metadata_len: *mut i32,
    encrypted_header_ptr: *const i8,
    encrypted_header_len: i32,
    authentication_data_ptr: *const i8,
    authentication_data_len: i32,
    cache_handle: i32,
) -> i32 {
    let encrypted_header_bytes = ffi_read_bytes!(
        "encrypted header",
        encrypted_header_ptr,
        encrypted_header_len
    );
    let encrypted_header = ffi_unwrap!(
        EncryptedHeader::deserialize(encrypted_header_bytes),
        "error deserializing encrypted header",
        ErrorCode::Serialization
    );
    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let map = DECRYPTION_CACHE_MAP
        .read()
        .expect("a read mutex on the decryption cache failed");
    let cache = if let Some(cache) = map.get(&cache_handle) {
        cache
    } else {
        ffi_bail!(format!(
            "Hybrid Cipher: no decryption cache with handle: {cache_handle}",
        ));
    };

    let header = ffi_unwrap!(
        encrypted_header.decrypt(&Covercrypt::default(), &cache.usk, authentication_data),
        "error decrypting CoverCrypt header",
        ErrorCode::Decryption
    );

    if header_metadata_ptr.is_null() {
        *header_metadata_len = 0;
        ffi_write_bytes!(
            "symmetric key",
            &header.symmetric_key,
            symmetric_key_ptr,
            symmetric_key_len
        );
    } else {
        let metadata = header.metadata.unwrap_or_default();
        ffi_write_bytes!(
            "symmetric key",
            &header.symmetric_key,
            symmetric_key_ptr,
            symmetric_key_len,
            "header metadata",
            &metadata,
            header_metadata_ptr,
            header_metadata_len
        );
    }
}

#[no_mangle]
/// Decrypts an encrypted header, returning the symmetric key and header
/// metadata if any.
///
/// No header metadata is returned if `header_metadata_ptr` is `NULL`.
///
/// # Safety
pub unsafe extern "C" fn h_decrypt_header(
    symmetric_key_ptr: *mut i8,
    symmetric_key_len: *mut i32,
    header_metadata_ptr: *mut i8,
    header_metadata_len: *mut i32,
    encrypted_header_ptr: *const i8,
    encrypted_header_len: i32,
    authentication_data_ptr: *const i8,
    authentication_data_len: i32,
    usk_ptr: *const i8,
    usk_len: i32,
) -> i32 {
    let usk_bytes = ffi_read_bytes!("user secret key", usk_ptr, usk_len);
    let usk = ffi_unwrap!(
        UserSecretKey::deserialize(usk_bytes),
        "error deserializing user secret key",
        ErrorCode::Serialization
    );
    let encrypted_header_bytes = ffi_read_bytes!(
        "encrypted header",
        encrypted_header_ptr,
        encrypted_header_len
    );
    let encrypted_header = ffi_unwrap!(
        EncryptedHeader::deserialize(encrypted_header_bytes),
        "encrypted header",
        ErrorCode::Serialization
    );

    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let decrypted_header = ffi_unwrap!(
        encrypted_header.decrypt(&Covercrypt::default(), &usk, authentication_data),
        "error decrypting CoverCrypt header",
        ErrorCode::Decryption
    );

    if header_metadata_ptr.is_null() {
        *header_metadata_len = 0;
        ffi_write_bytes!(
            "symmetric key",
            &decrypted_header.symmetric_key,
            symmetric_key_ptr,
            symmetric_key_len
        );
    } else {
        let metadata = decrypted_header.metadata.unwrap_or_default();
        ffi_write_bytes!(
            "symmetric key",
            &decrypted_header.symmetric_key,
            symmetric_key_ptr,
            symmetric_key_len,
            "header metadata",
            &metadata,
            header_metadata_ptr,
            header_metadata_len
        );
    }
}

#[no_mangle]
///
/// # Safety
pub const unsafe extern "C" fn h_symmetric_encryption_overhead() -> i32 {
    (Aes256Gcm::NONCE_LENGTH + Aes256Gcm::MAC_LENGTH) as i32
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_dem_encrypt(
    ciphertext_ptr: *mut i8,
    ciphertext_len: *mut i32,
    symmetric_key_ptr: *const i8,
    symmetric_key_len: i32,
    authentication_data_ptr: *const i8,
    authentication_data_len: i32,
    plaintext_ptr: *const i8,
    plaintext_len: i32,
) -> i32 {
    let plaintext = ffi_read_bytes!("plaintext", plaintext_ptr, plaintext_len);
    let symmetric_key_bytes =
        ffi_read_bytes!("symmetric key", symmetric_key_ptr, symmetric_key_len);
    let symmetric_key_fixed_length = ffi_unwrap!(
        symmetric_key_bytes.try_into(),
        "error converting to fixed length",
        ErrorCode::Serialization
    );
    let symmetric_key = ffi_unwrap!(
        SymmetricKey::try_from_bytes(symmetric_key_fixed_length),
        "error parsing symmetric key",
        ErrorCode::Serialization
    );
    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let ciphertext = ffi_unwrap!(
        Covercrypt::default().encrypt(&symmetric_key, plaintext, authentication_data),
        "error encrypting plaintext",
        ErrorCode::Encryption
    );

    ffi_write_bytes!("ciphertext", &ciphertext, ciphertext_ptr, ciphertext_len);
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_dem_decrypt(
    plaintext_ptr: *mut i8,
    plaintext_len: *mut i32,
    symmetric_key_ptr: *const i8,
    symmetric_key_len: i32,
    authentication_data_ptr: *const i8,
    authentication_data_len: i32,
    ciphertext_ptr: *const i8,
    ciphertext_len: i32,
) -> i32 {
    let ciphertext = ffi_read_bytes!("ciphertext", ciphertext_ptr, ciphertext_len);
    let symmetric_key_bytes =
        ffi_read_bytes!("symmetric key", symmetric_key_ptr, symmetric_key_len);
    let symmetric_key_fixed_length = ffi_unwrap!(
        symmetric_key_bytes.try_into(),
        "error converting to fixed length",
        ErrorCode::Serialization
    );
    let symmetric_key = ffi_unwrap!(
        SymmetricKey::try_from_bytes(symmetric_key_fixed_length),
        "error parsing symmetric key",
        ErrorCode::Serialization
    );
    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let plaintext = ffi_unwrap!(
        Covercrypt::default().decrypt(&symmetric_key, ciphertext, authentication_data),
        "error decrypting symmetric ciphertext",
        ErrorCode::Decryption
    );

    ffi_write_bytes!("plaintext", &plaintext, plaintext_ptr, plaintext_len);
}

#[no_mangle]
/// Hybrid encrypt some content
///
/// # Safety
pub unsafe extern "C" fn h_hybrid_encrypt(
    ciphertext_ptr: *mut i8,
    ciphertext_len: *mut i32,
    policy_ptr: *const i8,
    policy_len: i32,
    mpk_ptr: *const i8,
    mpk_len: i32,
    encryption_policy_ptr: *const i8,
    plaintext_ptr: *const i8,
    plaintext_len: i32,
    header_metadata_ptr: *const i8,
    header_metadata_len: i32,
    authentication_data_ptr: *const i8,
    authentication_data_len: i32,
) -> i32 {
    let policy_bytes = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy = ffi_unwrap!(
        Policy::parse_and_convert(policy_bytes),
        "error deserializing policy",
        ErrorCode::Serialization
    );
    let encryption_policy_string = ffi_read_string!("encryption policy", encryption_policy_ptr);
    let encryption_policy = ffi_unwrap!(
        AccessPolicy::from_boolean_expression(&encryption_policy_string),
        "error parsing encryption policy",
        ErrorCode::Serialization
    );
    let plaintext = ffi_read_bytes!("plaintext", plaintext_ptr, plaintext_len);
    let mpk_bytes = ffi_read_bytes!("public key", mpk_ptr, mpk_len);
    let mpk = ffi_unwrap!(
        MasterPublicKey::deserialize(mpk_bytes),
        "error deserializing public key",
        ErrorCode::Serialization
    );
    let header_metadata = if header_metadata_ptr.is_null() || header_metadata_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "header metadata",
            header_metadata_ptr,
            header_metadata_len
        ))
    };

    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let (symmetric_key, encrypted_header) = ffi_unwrap!(
        EncryptedHeader::generate(
            &Covercrypt::default(),
            &policy,
            &mpk,
            &encryption_policy,
            header_metadata,
            authentication_data
        ),
        "error encrypting CoverCrypt header",
        ErrorCode::Encryption
    );

    let ciphertext = ffi_unwrap!(
        Covercrypt::default().encrypt(&symmetric_key, plaintext, authentication_data,),
        "error encrypting plaintext",
        ErrorCode::Encryption
    );

    let mut ser = Serializer::with_capacity(encrypted_header.length() + ciphertext.len());
    ffi_unwrap!(
        ser.write(&encrypted_header),
        "error serializing encrypted CoverCrypt header",
        ErrorCode::Serialization
    );
    ffi_unwrap!(
        ser.write_array(&ciphertext),
        "error deserializing symmetric ciphertext",
        ErrorCode::Serialization
    );
    let bytes = ser.finalize();

    ffi_write_bytes!("ciphertext", &bytes, ciphertext_ptr, ciphertext_len);
}

#[no_mangle]
/// Hybrid decrypt some content.
///
/// No header metadata is returned if `header_metadata_ptr` is `NULL`.
///
/// # Safety
pub unsafe extern "C" fn h_hybrid_decrypt(
    plaintext_ptr: *mut i8,
    plaintext_len: *mut i32,
    header_metadata_ptr: *mut i8,
    header_metadata_len: *mut i32,
    ciphertext_ptr: *const i8,
    ciphertext_len: i32,
    authentication_data_ptr: *const i8,
    authentication_data_len: i32,
    usk_ptr: *const i8,
    usk_len: i32,
) -> i32 {
    let usk_bytes = ffi_read_bytes!("user secret key", usk_ptr, usk_len);
    let usk = ffi_unwrap!(
        UserSecretKey::deserialize(usk_bytes),
        "error deserializing user secret key",
        ErrorCode::Serialization
    );
    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let ciphertext = ffi_read_bytes!("ciphertext", ciphertext_ptr, ciphertext_len);
    let mut de = Deserializer::new(ciphertext);
    let encrypted_header = ffi_unwrap!(
        // this will read the exact header size
        de.read::<EncryptedHeader>(),
        "error deserializing encrypted CoverCrypt header",
        ErrorCode::Serialization
    );
    // the rest is the symmetric ciphertext
    let encrypted_content = de.finalize();

    // Decrypt header
    let decrypted_header = ffi_unwrap!(
        encrypted_header.decrypt(&Covercrypt::default(), &usk, authentication_data),
        "error decrypting CoverCrypt header",
        ErrorCode::Decryption
    );

    let plaintext = ffi_unwrap!(
        Covercrypt::default().decrypt(
            &decrypted_header.symmetric_key,
            &encrypted_content,
            authentication_data,
        ),
        "error decrypting symmetric ciphertext",
        ErrorCode::Decryption
    );

    if header_metadata_ptr.is_null() {
        *header_metadata_len = 0;
        ffi_write_bytes!("plaintext", &plaintext, plaintext_ptr, plaintext_len);
    } else {
        let metadata = decrypted_header.metadata.unwrap_or_default();
        ffi_write_bytes!(
            "plaintext",
            &plaintext,
            plaintext_ptr,
            plaintext_len,
            "header metadata",
            &metadata,
            header_metadata_ptr,
            header_metadata_len
        );
    }
}
