use core::ffi::c_size_t;
use std::ffi::{c_char, c_int, c_uchar};

use aes_gcm::aead::rand_core::SeedableRng;
use cloudproof_cover_crypt::reexport::crypto_core::{
    asymmetric_crypto::{
        curve25519::{X25519KeyPair, X25519PrivateKey, X25519PublicKey},
        ecies::{ecies_decrypt, ecies_encrypt, ecies_encrypt_get_overhead_size},
        DhKeyPair,
    },
    CsRng, KeyTrait,
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
    let key_pair: X25519KeyPair = X25519KeyPair::new(&mut rng);

    ffi_write_bytes!(
        "public_key_ptr",
        &key_pair.public_key().to_bytes(),
        public_key_ptr,
        public_key_len
        "private_key_ptr",
        &key_pair.private_key().to_bytes(),
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
    encrypt_flag: bool,
) -> c_int {
    let input_data_bytes = ffi_read_bytes!("input_data", input_data_ptr, input_data_len);
    let key_bytes = ffi_read_bytes!("key", key_ptr, key_len);

    let output = if encrypt_flag {
        let mut rng = CsRng::from_entropy();
        let public_key = ffi_unwrap!(
            X25519PublicKey::try_from_bytes(key_bytes),
            "ECIES deserializing public key"
        );
        // Encrypt the message
        ffi_unwrap!(
            ecies_encrypt::<
                CsRng,
                X25519KeyPair,
                { X25519KeyPair::PUBLIC_KEY_LENGTH },
                { X25519KeyPair::PRIVATE_KEY_LENGTH },
            >(&mut rng, &public_key, input_data_bytes, None, None),
            "ECIES encryption"
        )
    } else {
        let private_key = ffi_unwrap!(
            X25519PrivateKey::try_from_bytes(key_bytes),
            "ECIES deserializing private key"
        );
        // Decrypt the message
        ffi_unwrap!(
            ecies_decrypt::<
                X25519KeyPair,
                { X25519KeyPair::PUBLIC_KEY_LENGTH },
                { X25519KeyPair::PRIVATE_KEY_LENGTH },
            >(&private_key, input_data_bytes, None, None),
            "ECIES decryption"
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
) -> c_int {
    ecies(
        output_ptr,
        output_len,
        plaintext_ptr,
        plaintext_len,
        public_key_ptr,
        public_key_len,
        true,
    )
}

#[no_mangle]
pub unsafe extern "C" fn h_ecies_encrypt_get_overhead_size() -> c_size_t {
    ecies_encrypt_get_overhead_size::<{ X25519KeyPair::PUBLIC_KEY_LENGTH }>()
}

#[no_mangle]
pub unsafe extern "C" fn h_ecies_decrypt(
    output_ptr: *mut c_uchar,
    output_len: *mut c_int,
    ciphertext_ptr: *const c_char,
    ciphertext_len: c_int,
    private_key_ptr: *const c_char,
    private_key_len: c_int,
) -> c_int {
    ecies(
        output_ptr,
        output_len,
        ciphertext_ptr,
        ciphertext_len,
        private_key_ptr,
        private_key_len,
        false,
    )
}
