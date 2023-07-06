use cloudproof_cover_crypt::reexport::crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, Ecies, EciesX25519XChaCha20, FixedSizeCBytes,
    RandomFixedSizeCBytes, X25519PrivateKey, X25519PublicKey,
};
use js_sys::Uint8Array;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

#[wasm_bindgen]
pub fn webassembly_ecies_generate_key_pair() -> Result<Uint8Array, JsValue> {
    let mut rng = CsRng::from_entropy();
    let private_key = X25519PrivateKey::new(&mut rng);
    let public_key = X25519PublicKey::from(&private_key);

    let mut pk = public_key.to_bytes().to_vec();
    let sk = private_key.to_bytes();
    pk.extend_from_slice(&sk);

    Ok(Uint8Array::from(pk.as_slice()))
}

#[wasm_bindgen]
pub fn webassembly_ecies_encrypt(
    plaintext: Vec<u8>,
    public_key: Vec<u8>,
    authenticated_data: Vec<u8>,
) -> Result<Uint8Array, JsValue> {
    let mut rng = CsRng::from_entropy();
    let public_key: [u8; X25519PublicKey::LENGTH] = public_key.try_into().map_err(|_e| {
        JsValue::from_str(&format!(
            "ECIES error: public key length incorrect: expected {}",
            X25519PublicKey::LENGTH
        ))
    })?;
    let public_key = X25519PublicKey::try_from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("ECIES error: public key deserializing: {e:?}")))?;

    // Encrypt the message
    let ciphertext =
        EciesX25519XChaCha20::encrypt(&mut rng, &public_key, &plaintext, Some(&authenticated_data))
            .map_err(|e| JsValue::from_str(&format!("ECIES error: encryption: {e:?}")))?;

    Ok(Uint8Array::from(ciphertext.as_slice()))
}

#[wasm_bindgen]
pub fn webassembly_ecies_decrypt(
    ciphertext: Vec<u8>,
    private_key: Vec<u8>,
    authenticated_data: Vec<u8>,
) -> Result<Uint8Array, JsValue> {
    let private_key: [u8; X25519PrivateKey::LENGTH] = private_key.try_into().map_err(|_e| {
        JsValue::from_str(&format!(
            "ECIES error: private key length incorrect: expected {}",
            X25519PrivateKey::LENGTH
        ))
    })?;
    let private_key = X25519PrivateKey::try_from_bytes(private_key).map_err(|e| {
        JsValue::from_str(&format!("ECIES error: private key deserializing: {e:?}"))
    })?;

    let plaintext =
        EciesX25519XChaCha20::decrypt(&private_key, &ciphertext, Some(&authenticated_data))
            .map_err(|e| JsValue::from_str(&format!("ECIES error: decryption: {e:?}")))?;
    Ok(Uint8Array::from(plaintext.as_slice()))
}
