use aes_gcm::aead::rand_core::SeedableRng;
use cloudproof_cover_crypt::reexport::crypto_core::{
    asymmetric_crypto::{
        curve25519::{X25519KeyPair, X25519PrivateKey, X25519PublicKey},
        ecies::{ecies_decrypt, ecies_encrypt},
        DhKeyPair,
    },
    CsRng, KeyTrait,
};
use pyo3::{exceptions::PyException, pyclass, pymethods, PyResult};

#[pyclass]
pub struct Ecies;

#[pymethods]
impl Ecies {
    #[staticmethod]
    fn generate_key_pair() -> PyResult<(Vec<u8>, Vec<u8>)> {
        let mut rng = CsRng::from_entropy();
        let key_pair: X25519KeyPair = X25519KeyPair::new(&mut rng);
        Ok((
            key_pair.public_key().to_bytes().to_vec(),
            key_pair.private_key().to_bytes().to_vec(),
        ))
    }

    #[staticmethod]
    fn encrypt(plaintext: Vec<u8>, public_key_bytes: Vec<u8>) -> PyResult<Vec<u8>> {
        let mut rng = CsRng::from_entropy();
        let public_key = X25519PublicKey::try_from_bytes(&public_key_bytes)
            .map_err(|e| PyException::new_err(format!("ECIES deserializing public key: {e:?}")))?;

        // Encrypt the message
        let output = ecies_encrypt::<
            CsRng,
            X25519KeyPair,
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
        >(&mut rng, &public_key, &plaintext, None, None)
        .map_err(|e| PyException::new_err(format!("ECIES encryption: {e}")))?;
        Ok(output)
    }

    #[staticmethod]
    fn decrypt(ciphertext: Vec<u8>, private_key_bytes: Vec<u8>) -> PyResult<Vec<u8>> {
        let private_key = X25519PrivateKey::try_from_bytes(&private_key_bytes)
            .map_err(|e| PyException::new_err(format!("ECIES deserializing private key: {e:?}")))?;

        // decrypt the message
        let output = ecies_decrypt::<
            X25519KeyPair,
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
        >(&private_key, &ciphertext, None, None)
        .map_err(|e| PyException::new_err(format!("ECIES encryption: {e}")))?;
        Ok(output)
    }
}
