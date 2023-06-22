use aes_gcm::aead::rand_core::SeedableRng;
use cloudproof_cover_crypt::reexport::crypto_core::{
    asymmetric_crypto::{
        curve25519::{X25519KeyPair, X25519PrivateKey, X25519PublicKey},
        ecies::{ecies_decrypt, ecies_encrypt},
        DhKeyPair,
    },
    CsRng, KeyTrait,
};
use js_sys::Uint8Array;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

#[wasm_bindgen]
pub fn webassembly_ecies_generate_key_pair() -> Result<Uint8Array, JsValue> {
    let mut rng = CsRng::from_entropy();
    let key_pair: X25519KeyPair = X25519KeyPair::new(&mut rng);

    let mut pk = key_pair.public_key().to_bytes().to_vec();
    let sk = key_pair.private_key().to_bytes();
    pk.extend_from_slice(&sk);

    Ok(Uint8Array::from(pk.as_slice()))
}

#[wasm_bindgen]
pub fn webassembly_ecies_encrypt(
    plaintext: Vec<u8>,
    public_key: Vec<u8>,
) -> Result<Uint8Array, JsValue> {
    let mut rng = CsRng::from_entropy();
    let pk = X25519PublicKey::try_from_bytes(&public_key)
        .map_err(|e| JsValue::from_str(&format!("ECIES error: public key deserializing: {e:?}")))?;

    // Encrypt the message
    let ciphertext = ecies_encrypt::<
        CsRng,
        X25519KeyPair,
        { X25519KeyPair::PUBLIC_KEY_LENGTH },
        { X25519KeyPair::PRIVATE_KEY_LENGTH },
    >(&mut rng, &pk, &plaintext, None, None)
    .map_err(|e| JsValue::from_str(&format!("ECIES error: decryption: {e:?}")))?;

    Ok(Uint8Array::from(ciphertext.as_slice()))
}

#[wasm_bindgen]
pub fn webassembly_ecies_decrypt(
    ciphertext: Vec<u8>,
    private_key: Vec<u8>,
) -> Result<Uint8Array, JsValue> {
    let private_key = X25519PrivateKey::try_from_bytes(&private_key).map_err(|e| {
        JsValue::from_str(&format!("ECIES error: private key deserializing: {e:?}"))
    })?;

    // Decrypt the message
    let cleartext = ecies_decrypt::<
        X25519KeyPair,
        { X25519KeyPair::PUBLIC_KEY_LENGTH },
        { X25519KeyPair::PRIVATE_KEY_LENGTH },
    >(&private_key, &ciphertext, None, None)
    .map_err(|e| JsValue::from_str(&format!("ECIES error: decryption: {e:?}")))?;
    Ok(Uint8Array::from(cleartext.as_slice()))
}
