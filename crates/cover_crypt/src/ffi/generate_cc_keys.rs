use std::os::raw::{c_char, c_int};

use cosmian_cover_crypt::{
    abe_policy::{AccessPolicy, Policy},
    statics::{CoverCryptX25519Aes256, MasterSecretKey, PublicKey, UserSecretKey},
    CoverCrypt,
};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_ffi_utils::{ffi_read_bytes, ffi_read_string, ffi_unwrap, ffi_write_bytes};

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
    msk_ptr: *mut c_char,
    msk_len: *mut c_int,
    mpk_ptr: *mut c_char,
    mpk_len: *mut c_int,
    policy_ptr: *const c_char,
    policy_len: c_int,
) -> c_int {
    let policy_bytes = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy: Policy = ffi_unwrap!(Policy::try_from(policy_bytes), "error deserializing policy");

    let (msk, mpk) = ffi_unwrap!(
        CoverCryptX25519Aes256::default().generate_master_keys(&policy),
        "error generating master keys"
    );

    let msk_bytes = ffi_unwrap!(msk.try_to_bytes(), "error serializing master secret key");
    let mpk_bytes = ffi_unwrap!(mpk.try_to_bytes(), "error serializing public key");
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

    0
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
    usk_ptr: *mut c_char,
    usk_len: *mut c_int,
    msk_ptr: *const c_char,
    msk_len: c_int,
    user_policy_ptr: *const c_char,
    policy_ptr: *const c_char,
    policy_len: c_int,
) -> c_int {
    let msk_bytes = ffi_read_bytes!("master secret key", msk_ptr, msk_len);
    let msk = ffi_unwrap!(
        MasterSecretKey::try_from_bytes(msk_bytes),
        "error deserializing master secret key"
    );
    let policy_bytes = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy = ffi_unwrap!(
        Policy::parse_and_convert(policy_bytes),
        "error deserializing policy"
    );
    let user_policy_string = ffi_read_string!("access policy", user_policy_ptr);
    let user_policy = ffi_unwrap!(
        AccessPolicy::from_boolean_expression(user_policy_string.as_str()),
        "error parsing user policy"
    );

    let usk = ffi_unwrap!(
        CoverCryptX25519Aes256::default().generate_user_secret_key(&msk, &user_policy, &policy),
        "error generating user secret key"
    );

    let usk_bytes = ffi_unwrap!(usk.try_to_bytes(), "error serializing user secret key");
    ffi_write_bytes!("user secret key", &usk_bytes, usk_ptr, usk_len);

    0
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
    updated_msk_ptr: *mut c_char,
    updated_msk_len: *mut c_int,
    updated_mpk_ptr: *mut c_char,
    updated_mpk_len: *mut c_int,
    current_msk_ptr: *const c_char,
    current_msk_len: c_int,
    current_mpk_ptr: *const c_char,
    current_mpk_len: c_int,
    policy_ptr: *const c_char,
    policy_len: c_int,
) -> c_int {
    let msk_bytes = ffi_read_bytes!(
        "current master secret key",
        current_msk_ptr,
        current_msk_len
    );
    let mut msk = ffi_unwrap!(
        MasterSecretKey::try_from_bytes(msk_bytes),
        "error deserializing master secret key"
    );
    let mpk_bytes = ffi_read_bytes!("current public key", current_mpk_ptr, current_mpk_len);
    let mut mpk = ffi_unwrap!(
        PublicKey::try_from_bytes(mpk_bytes),
        "error deserializing public key"
    );
    let policy_bytes = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy = ffi_unwrap!(
        Policy::parse_and_convert(policy_bytes),
        "error deserializing policy"
    );

    ffi_unwrap!(
        CoverCryptX25519Aes256::default().update_master_keys(&policy, &mut msk, &mut mpk),
        "error updating master keys"
    );

    let msk_bytes = ffi_unwrap!(msk.try_to_bytes(), "error serializing master secret key");
    let mpk_bytes = ffi_unwrap!(mpk.try_to_bytes(), "error serializing public key");
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

    0
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
/// - `access_policy_ptr`               : Access policy of the user secret key
///   (JSON)
/// - `policy_ptr`                      : Policy to use to update the master
///   keys (JSON)
/// - `preserve_old_partitions_access`  : set to 1 to preserve the user access
///   to the rotated partitions
/// # Safety
pub unsafe extern "C" fn h_refresh_user_secret_key(
    updated_usk_ptr: *mut c_char,
    updated_usk_len: *mut c_int,
    msk_ptr: *const c_char,
    msk_len: c_int,
    current_usk_ptr: *const c_char,
    current_usk_len: c_int,
    user_policy_ptr: *const c_char,
    policy_ptr: *const c_char,
    policy_len: c_int,
    preserve_old_partitions_access: c_int,
) -> c_int {
    let msk_bytes = ffi_read_bytes!("master secret key", msk_ptr, msk_len);
    let msk = ffi_unwrap!(
        MasterSecretKey::try_from_bytes(msk_bytes),
        "error deserializing master secret key"
    );
    let usk_bytes = ffi_read_bytes!("current user secret key", current_usk_ptr, current_usk_len);
    let mut usk = ffi_unwrap!(
        UserSecretKey::try_from_bytes(usk_bytes),
        "error deserializing user secret key"
    );
    let policy_bytes = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy = ffi_unwrap!(
        Policy::parse_and_convert(policy_bytes),
        "error deserializing policy"
    );
    let user_policy_string = ffi_read_string!("user policy", user_policy_ptr);
    let user_policy = ffi_unwrap!(
        AccessPolicy::from_boolean_expression(&user_policy_string),
        "error parsing user policy"
    );

    ffi_unwrap!(
        CoverCryptX25519Aes256::default().refresh_user_secret_key(
            &mut usk,
            &user_policy,
            &msk,
            &policy,
            preserve_old_partitions_access != 0
        ),
        "error refreshing user secret key"
    );

    let usk_bytes = ffi_unwrap!(usk.try_to_bytes(), "error serializing user secret key");
    ffi_write_bytes!(
        "updated user secret key",
        &usk_bytes,
        updated_usk_ptr,
        updated_usk_len
    );

    0
}
