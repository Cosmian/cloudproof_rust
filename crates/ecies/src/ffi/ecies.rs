use cosmian_crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, Ecies, EciesSalsaSealBox, FixedSizeCBytes,
    X25519PrivateKey, X25519PublicKey,
};
use cosmian_ffi_utils::{ffi_read_bytes, ffi_unwrap, ffi_write_bytes};

#[no_mangle]
pub unsafe extern "C" fn h_ecies_x25519_generate_key_pair(
    public_key_ptr: *mut u8,
    public_key_len: *mut i32,
    private_key_ptr: *mut u8,
    private_key_len: *mut i32,
) -> i32 {
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

unsafe extern "C" fn ecies_salsa_seal_box(
    output_ptr: *mut u8,
    output_len: *mut i32,
    input_data_ptr: *const i8,
    input_data_len: i32,
    key_ptr: *const i8,
    key_len: i32,
    authenticated_data_ptr: *const i8,
    authenticated_data_len: i32,
    encrypt_flag: bool,
) -> i32 {
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
            EciesSalsaSealBox::encrypt(
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
            EciesSalsaSealBox::decrypt(
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
pub unsafe extern "C" fn h_ecies_salsa_seal_box_encrypt(
    output_ptr: *mut u8,
    output_len: *mut i32,
    plaintext_ptr: *const i8,
    plaintext_len: i32,
    public_key_ptr: *const i8,
    public_key_len: i32,
    authentication_data_ptr: *const i8,
    authentication_data_len: i32,
) -> i32 {
    ecies_salsa_seal_box(
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
pub unsafe extern "C" fn h_ecies_salsa_seal_box_get_encryption_overhead() -> u32 {
    EciesSalsaSealBox::ENCRYPTION_OVERHEAD as u32
}

#[no_mangle]
pub unsafe extern "C" fn h_ecies_salsa_seal_box_decrypt(
    output_ptr: *mut u8,
    output_len: *mut i32,
    ciphertext_ptr: *const i8,
    ciphertext_len: i32,
    private_key_ptr: *const i8,
    private_key_len: i32,
    authentication_data_ptr: *const i8,
    authentication_data_len: i32,
) -> i32 {
    ecies_salsa_seal_box(
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
