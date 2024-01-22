use cosmian_cover_crypt::{
    abe_policy::{AccessPolicy, Policy},
    Covercrypt, MasterPublicKey, MasterSecretKey, UserSecretKey,
};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_ffi_utils::{ffi_read_bytes, ffi_read_string, ffi_unwrap, ffi_write_bytes, ErrorCode};

#[no_mangle]
/// Generates the master authority keys for supplied Policy.
///
///  - `msk_ptr`    : Output buffer containing the master secret key
///  - `msk_len`    : Size of the master secret key output buffer
///  - `mpk_ptr`    : Output buffer containing the master public key
///  - `mpk_len`    : Size of the master public key output buffer
///  - `policy_ptr` : Policy to use to generate the keys
///  - `policy_len` : Size of the `Policy` to use to generate the keys
///
/// # Safety
pub unsafe extern "C" fn h_generate_master_keys(
    msk_ptr: *mut i8,
    msk_len: *mut i32,
    mpk_ptr: *mut i8,
    mpk_len: *mut i32,
    policy_ptr: *const i8,
    policy_len: i32,
) -> i32 {
    let policy_bytes = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy: Policy = ffi_unwrap!(
        Policy::try_from(policy_bytes),
        "error deserializing policy",
        ErrorCode::Serialization
    );

    let (msk, mpk) = ffi_unwrap!(
        Covercrypt::default().generate_master_keys(&policy),
        "error generating master keys",
        ErrorCode::Covercrypt
    );

    let msk_bytes = ffi_unwrap!(
        msk.serialize(),
        "error serializing master secret key",
        ErrorCode::Serialization
    );
    let mpk_bytes = ffi_unwrap!(
        mpk.serialize(),
        "error serializing public key",
        ErrorCode::Serialization
    );
    ffi_write_bytes!(
        "master secret key",
        &msk_bytes,
        msk_ptr,
        msk_len,
        "public key",
        &mpk_bytes,
        mpk_ptr,
        mpk_len
    );
}

#[no_mangle]
/// Generates a user secret key for the given access policy
///
/// - `usk_ptr`             : Output buffer containing user secret key
/// - `usk_len`             : Size of the output buffer
/// - `msk_ptr`             : Master secret key (required for this generation)
/// - `msk_len`             : Master secret key length
/// - `user_policy_ptr`     : null terminated access policy string
/// - `policy_ptr`          : bytes of the policy used to generate the keys
/// - `policy_len`          : length of the policy (in bytes)
/// # Safety
pub unsafe extern "C" fn h_generate_user_secret_key(
    usk_ptr: *mut i8,
    usk_len: *mut i32,
    msk_ptr: *const i8,
    msk_len: i32,
    user_policy_ptr: *const i8,
    policy_ptr: *const i8,
    policy_len: i32,
) -> i32 {
    let msk_bytes = ffi_read_bytes!("master secret key", msk_ptr, msk_len);
    let msk = ffi_unwrap!(
        MasterSecretKey::deserialize(msk_bytes),
        "error deserializing master secret key",
        ErrorCode::Serialization
    );
    let policy_bytes = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy = ffi_unwrap!(
        Policy::parse_and_convert(policy_bytes),
        "error deserializing policy",
        ErrorCode::Serialization
    );
    let user_policy_string = ffi_read_string!("access policy", user_policy_ptr);
    let user_policy = ffi_unwrap!(
        AccessPolicy::from_boolean_expression(user_policy_string.as_str()),
        "error parsing user policy",
        ErrorCode::Serialization
    );

    let usk = ffi_unwrap!(
        Covercrypt::default().generate_user_secret_key(&msk, &user_policy, &policy),
        "error generating user secret key",
        ErrorCode::Covercrypt
    );

    let usk_bytes = ffi_unwrap!(
        usk.serialize(),
        "error serializing user secret key",
        ErrorCode::Serialization
    );
    ffi_write_bytes!("user secret key", &usk_bytes, usk_ptr, usk_len);
}

#[no_mangle]
/// Updates the master keys according to the given policy.
///
/// Cf (`CoverCrypt::update_master_keys`)[`CoverCrypt::update_master_keys`].
///
/// - `updated_msk_ptr` : Output buffer containing the updated master secret key
/// - `updated_msk_len` : Size of the updated master secret key output buffer
/// - `updated_mpk_ptr` : Output buffer containing the updated master public key
/// - `updated_mpk_len` : Size of the updated master public key output buffer
/// - `current_msk_ptr` : current master secret key
/// - `current_msk_len` : current master secret key length
/// - `current_mpk_ptr` : current master public key
/// - `current_mpk_len` : current master public key length
/// - `policy_ptr`      : Policy to use to update the master keys (JSON)
/// # Safety
pub unsafe extern "C" fn h_update_master_keys(
    updated_msk_ptr: *mut i8,
    updated_msk_len: *mut i32,
    updated_mpk_ptr: *mut i8,
    updated_mpk_len: *mut i32,
    current_msk_ptr: *const i8,
    current_msk_len: i32,
    current_mpk_ptr: *const i8,
    current_mpk_len: i32,
    policy_ptr: *const i8,
    policy_len: i32,
) -> i32 {
    let msk_bytes = ffi_read_bytes!(
        "current master secret key",
        current_msk_ptr,
        current_msk_len
    );
    let mut msk = ffi_unwrap!(
        MasterSecretKey::deserialize(msk_bytes),
        "error deserializing master secret key",
        ErrorCode::Serialization
    );
    let mpk_bytes = ffi_read_bytes!("current public key", current_mpk_ptr, current_mpk_len);
    let mut mpk = ffi_unwrap!(
        MasterPublicKey::deserialize(mpk_bytes),
        "error deserializing public key",
        ErrorCode::Serialization
    );
    let policy_bytes = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy = ffi_unwrap!(
        Policy::parse_and_convert(policy_bytes),
        "error deserializing policy",
        ErrorCode::Serialization
    );

    ffi_unwrap!(
        Covercrypt::default().update_master_keys(&policy, &mut msk, &mut mpk),
        "error updating master keys",
        ErrorCode::Covercrypt
    );

    let msk_bytes = ffi_unwrap!(
        msk.serialize(),
        "error serializing master secret key",
        ErrorCode::Serialization
    );
    let mpk_bytes = ffi_unwrap!(
        mpk.serialize(),
        "error serializing public key",
        ErrorCode::Serialization
    );
    ffi_write_bytes!(
        "updated master secret key",
        &msk_bytes,
        updated_msk_ptr,
        updated_msk_len,
        "updated public key",
        &mpk_bytes,
        updated_mpk_ptr,
        updated_mpk_len
    );
}

#[no_mangle]
/// Rekey the master keys according to the given access policy.
///
/// Cf (`CoverCrypt::rekey_master_keys`)[`CoverCrypt::rekey_master_keys`].
///
/// - `updated_msk_ptr`   : Output buffer containing the updated master secret
///   key
/// - `updated_msk_len`   : Size of the updated master secret key output buffer
/// - `updated_mpk_ptr`   : Output buffer containing the updated master public
///   key
/// - `updated_mpk_len`   : Size of the updated master public key output buffer
/// - `current_msk_ptr`   : current master secret key
/// - `current_msk_len`   : current master secret key length
/// - `current_mpk_ptr`   : current master public key
/// - `current_mpk_len`   : current master public key length
/// - `access_policy_ptr` : Policy to use to update the master keys (JSON)
/// - `policy_ptr`        : Policy to use to update the master keys (JSON)
/// # Safety
pub unsafe extern "C" fn h_rekey_master_keys(
    updated_msk_ptr: *mut i8,
    updated_msk_len: *mut i32,
    updated_mpk_ptr: *mut i8,
    updated_mpk_len: *mut i32,
    current_msk_ptr: *const i8,
    current_msk_len: i32,
    current_mpk_ptr: *const i8,
    current_mpk_len: i32,
    access_policy_ptr: *const i8,
    policy_ptr: *const i8,
    policy_len: i32,
) -> i32 {
    let msk_bytes = ffi_read_bytes!(
        "current master secret key",
        current_msk_ptr,
        current_msk_len
    );
    let mut msk = ffi_unwrap!(
        MasterSecretKey::deserialize(msk_bytes),
        "error deserializing master secret key",
        ErrorCode::Serialization
    );
    let mpk_bytes = ffi_read_bytes!("current public key", current_mpk_ptr, current_mpk_len);
    let mut mpk = ffi_unwrap!(
        MasterPublicKey::deserialize(mpk_bytes),
        "error deserializing public key",
        ErrorCode::Serialization
    );
    let access_policy_string = ffi_read_string!("access policy", access_policy_ptr);
    let access_policy = ffi_unwrap!(
        AccessPolicy::from_boolean_expression(&access_policy_string),
        "error parsing user policy",
        ErrorCode::Serialization
    );
    let policy_bytes = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy = ffi_unwrap!(
        Policy::parse_and_convert(policy_bytes),
        "error deserializing policy",
        ErrorCode::Serialization
    );

    ffi_unwrap!(
        Covercrypt::default().rekey_master_keys(&access_policy, &policy, &mut msk, &mut mpk),
        "error rekeying master keys",
        ErrorCode::Covercrypt
    );

    let msk_bytes = ffi_unwrap!(
        msk.serialize(),
        "error serializing master secret key",
        ErrorCode::Serialization
    );
    let mpk_bytes = ffi_unwrap!(
        mpk.serialize(),
        "error serializing public key",
        ErrorCode::Serialization
    );
    ffi_write_bytes!(
        "updated master secret key",
        &msk_bytes,
        updated_msk_ptr,
        updated_msk_len,
        "updated public key",
        &mpk_bytes,
        updated_mpk_ptr,
        updated_mpk_len
    );
}

#[no_mangle]
/// Removes old keys associated to the given master key from the master
/// keys. This will permanently remove access to old ciphers.
///
/// Cf (`CoverCrypt::prune_master_secret_key`)[`CoverCrypt::prune_master_secret_key`].
///
/// - `updated_msk_ptr`   : Output buffer containing the updated master secret
///   key
/// - `updated_msk_len`   : Size of the updated master secret key output buffer
/// - `updated_mpk_ptr`   : Output buffer containing the updated master public
///   key
/// - `updated_mpk_len`   : Size of the updated master public key output buffer
/// - `current_msk_ptr`   : current master secret key
/// - `current_msk_len`   : current master secret key length
/// - `current_mpk_ptr`   : current master public key
/// - `current_mpk_len`   : current master public key length
/// - `access_policy_ptr` : Policy to use to update the master keys (JSON)
/// - `policy_ptr`        : Policy to use to update the master keys (JSON)
/// # Safety
pub unsafe extern "C" fn h_prune_master_secret_key(
    updated_msk_ptr: *mut i8,
    updated_msk_len: *mut i32,
    current_msk_ptr: *const i8,
    current_msk_len: i32,
    access_policy_ptr: *const i8,
    policy_ptr: *const i8,
    policy_len: i32,
) -> i32 {
    let msk_bytes = ffi_read_bytes!(
        "current master secret key",
        current_msk_ptr,
        current_msk_len
    );
    let mut msk = ffi_unwrap!(
        MasterSecretKey::deserialize(msk_bytes),
        "error deserializing master secret key",
        ErrorCode::Serialization
    );
    let access_policy_string = ffi_read_string!("access policy", access_policy_ptr);
    let access_policy = ffi_unwrap!(
        AccessPolicy::from_boolean_expression(&access_policy_string),
        "error parsing user policy",
        ErrorCode::Serialization
    );
    let policy_bytes = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy = ffi_unwrap!(
        Policy::parse_and_convert(policy_bytes),
        "error deserializing policy",
        ErrorCode::Serialization
    );

    ffi_unwrap!(
        Covercrypt::default().prune_master_secret_key(&access_policy, &policy, &mut msk),
        "error pruning master secret key",
        ErrorCode::Covercrypt
    );

    let msk_bytes = ffi_unwrap!(
        msk.serialize(),
        "error serializing master secret key",
        ErrorCode::Serialization
    );

    ffi_write_bytes!(
        "updated master secret key",
        &msk_bytes,
        updated_msk_ptr,
        updated_msk_len,
    );
}

#[no_mangle]
/// Refreshes the user secret key according to the given master key and access
/// policy.
///
/// Cf [`CoverCrypt::refresh_user_secret_key()`](CoverCrypt::refresh_user_secret_key).
///
/// - `updated_usk_ptr`                 : Output buffer containing the updated
///   user secret key
/// - `updated_usk_len`                 : Size of the updated user secret key
///   output buffer
/// - `msk_ptr`                         : master secret key
/// - `msk_len`                         : master secret key length
/// - `current_usk_ptr`                 : current user secret key
/// - `current_usk_len`                 : current user secret key length
/// - `preserve_old_partitions_access`  : set to 1 to preserve the user access
///   to the rotated partitions
/// # Safety
pub unsafe extern "C" fn h_refresh_user_secret_key(
    updated_usk_ptr: *mut i8,
    updated_usk_len: *mut i32,
    msk_ptr: *const i8,
    msk_len: i32,
    current_usk_ptr: *const i8,
    current_usk_len: i32,
    preserve_old_partitions_access: i32,
) -> i32 {
    let msk_bytes = ffi_read_bytes!("master secret key", msk_ptr, msk_len);
    let msk = ffi_unwrap!(
        MasterSecretKey::deserialize(msk_bytes),
        "error deserializing master secret key",
        ErrorCode::Serialization
    );
    let usk_bytes = ffi_read_bytes!("current user secret key", current_usk_ptr, current_usk_len);
    let mut usk = ffi_unwrap!(
        UserSecretKey::deserialize(usk_bytes),
        "error deserializing user secret key",
        ErrorCode::Serialization
    );

    ffi_unwrap!(
        Covercrypt::default().refresh_user_secret_key(
            &mut usk,
            &msk,
            preserve_old_partitions_access != 0
        ),
        "error refreshing user secret key",
        ErrorCode::Covercrypt
    );

    let usk_bytes = ffi_unwrap!(
        usk.serialize(),
        "error serializing user secret key",
        ErrorCode::Serialization
    );
    ffi_write_bytes!(
        "updated user secret key",
        &usk_bytes,
        updated_usk_ptr,
        updated_usk_len
    );
}
