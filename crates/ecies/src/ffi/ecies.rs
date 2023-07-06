use core::ffi::c_size_t;
use std::ffi::{c_char, c_int, c_uchar};

use cloudproof_cover_crypt::reexport::crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, Ecies, EciesX25519XChaCha20, FixedSizeCBytes,
    RandomFixedSizeCBytes, X25519PrivateKey, X25519PublicKey,
};
use cosmian_ffi_utils::{ffi_read_bytes, ffi_unwrap, ffi_write_bytes};

#[no_mangle]
pub unsafe extern "C" fn h_ecies_generate_key_pair(
    public_key_ptr: *mut c_uchar,
    public_key_len: *mut c_int,
    private_key_ptr: *mut c_uchar,
    private_key_len: *mut c_int,
) -> c_int {
    let mut rng = CsRng::from_entropy();
    let private_key = X25519PrivateKey::new(&mut rng);
    let public_key = X25519PublicKey::from(&private_key);

    ffi_write_bytes!(
        "public_key_ptr",
        &public_key.to_bytes(),
        public_key_ptr,
        public_key_len
        "private_key_ptr",
        &private_key.to_bytes(),
        private_key_ptr,
        private_key_len
    );

    0
}

unsafe extern "C" fn ecies(
    output_ptr: *mut c_uchar,
    output_len: *mut c_int,
    input_data_ptr: *const c_char,
    input_data_len: c_int,
    key_ptr: *const c_char,
    key_len: c_int,
    authenticated_data_ptr: *const c_char,
    authenticated_data_len: c_int,
    encrypt_flag: bool,
) -> c_int {
    let input_data_bytes = ffi_read_bytes!("input_data", input_data_ptr, input_data_len);
    let key_bytes = ffi_read_bytes!("key", key_ptr, key_len);
    let authenticated_data_bytes = ffi_read_bytes!(
        "authenticated_data",
        authenticated_data_ptr,
        authenticated_data_len
    );

    let output = if encrypt_flag {
        let mut rng = CsRng::from_entropy();
        let public_key: [u8; X25519PublicKey::LENGTH] = ffi_unwrap!(
            key_bytes.try_into(),
            format!(
                "ECIES error: public key length incorrect: expected {}",
                X25519PublicKey::LENGTH
            )
        );
        let public_key = ffi_unwrap!(
            X25519PublicKey::try_from_bytes(public_key),
            format!("ECIES error: public key deserializing")
        );

        ffi_unwrap!(
            EciesX25519XChaCha20::encrypt(
                &mut rng,
                &public_key,
                input_data_bytes,
                Some(authenticated_data_bytes)
            ),
            "ECIES error: encryption"
        )
    } else {
        let private_key: [u8; X25519PrivateKey::LENGTH] = ffi_unwrap!(
            key_bytes.try_into(),
            format!(
                "ECIES error: private key length incorrect: expected {}",
                X25519PrivateKey::LENGTH
            )
        );
        let private_key = ffi_unwrap!(
            X25519PrivateKey::try_from_bytes(private_key),
            format!("ECIES error: private key deserializing")
        );

        ffi_unwrap!(
            EciesX25519XChaCha20::decrypt(
                &private_key,
                input_data_bytes,
                Some(authenticated_data_bytes)
            ),
            "ECIES error: decryption"
        )
    };
    ffi_write_bytes!("output_ptr", &output, output_ptr, output_len);

    0
}

#[no_mangle]
pub unsafe extern "C" fn h_ecies_encrypt(
    output_ptr: *mut c_uchar,
    output_len: *mut c_int,
    plaintext_ptr: *const c_char,
    plaintext_len: c_int,
    public_key_ptr: *const c_char,
    public_key_len: c_int,
    authentication_data_ptr: *const c_char,
    authentication_data_len: c_int,
) -> c_int {
    ecies(
        output_ptr,
        output_len,
        plaintext_ptr,
        plaintext_len,
        public_key_ptr,
        public_key_len,
        authentication_data_ptr,
        authentication_data_len,
        true,
    )
}

#[no_mangle]
pub unsafe extern "C" fn h_ecies_encrypt_get_overhead_size() -> c_size_t {
    EciesX25519XChaCha20::ENCRYPTION_OVERHEAD
}

#[no_mangle]
pub unsafe extern "C" fn h_ecies_decrypt(
    output_ptr: *mut c_uchar,
    output_len: *mut c_int,
    ciphertext_ptr: *const c_char,
    ciphertext_len: c_int,
    private_key_ptr: *const c_char,
    private_key_len: c_int,
    authentication_data_ptr: *const c_char,
    authentication_data_len: c_int,
) -> c_int {
    ecies(
        output_ptr,
        output_len,
        ciphertext_ptr,
        ciphertext_len,
        private_key_ptr,
        private_key_len,
        authentication_data_ptr,
        authentication_data_len,
        false,
    )
}
