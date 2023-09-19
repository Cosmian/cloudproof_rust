use cosmian_crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, Ecies as EciesRust,
    EciesSalsaSealBox as EciesSalsaSealBoxRust, FixedSizeCBytes, X25519PrivateKey, X25519PublicKey,
};
use pyo3::{exceptions::PyException, pyclass, pymethods, PyResult};

#[pyclass]
pub struct EciesSalsaSealBox;

#[pymethods]
impl EciesSalsaSealBox {
    #[staticmethod]
    fn generate_key_pair() -> PyResult<(Vec<u8>, Vec<u8>)> {
        let mut rng = CsRng::from_entropy();
        let private_key = X25519PrivateKey::new(&mut rng);
        let public_key = X25519PublicKey::from(&private_key);
        Ok((
            public_key.to_bytes().to_vec(),
            private_key.to_bytes().to_vec(),
        ))
    }

    #[staticmethod]
    fn encrypt(
        plaintext: Vec<u8>,
        public_key: Vec<u8>,
        authenticated_data: Vec<u8>,
    ) -> PyResult<Vec<u8>> {
        let mut rng = CsRng::from_entropy();
        let public_key: [u8; X25519PublicKey::LENGTH] = public_key.try_into().map_err(|_e| {
            PyException::new_err(format!(
                "ECIES error: public key length incorrect: expected {}",
                X25519PublicKey::LENGTH
            ))
        })?;
        let public_key = X25519PublicKey::try_from_bytes(public_key).map_err(|e| {
            PyException::new_err(format!("ECIES error: public key deserializing: {e:?}"))
        })?;

        // Encrypt the message
        let ciphertext = EciesSalsaSealBoxRust::encrypt(
            &mut rng,
            &public_key,
            &plaintext,
            Some(&authenticated_data),
        )
        .map_err(|e| PyException::new_err(format!("ECIES error: encryption: {e:?}")))?;
        Ok(ciphertext)
    }

    #[staticmethod]
    fn decrypt(
        ciphertext: Vec<u8>,
        private_key: Vec<u8>,
        authenticated_data: Vec<u8>,
    ) -> PyResult<Vec<u8>> {
        let private_key: [u8; X25519PrivateKey::LENGTH] = private_key.try_into().map_err(|_e| {
            PyException::new_err(format!(
                "ECIES error: private key length incorrect: expected {}",
                X25519PrivateKey::LENGTH
            ))
        })?;
        let private_key = X25519PrivateKey::try_from_bytes(private_key).map_err(|e| {
            PyException::new_err(format!("ECIES error: private key deserializing: {e:?}"))
        })?;

        let plaintext =
            EciesSalsaSealBoxRust::decrypt(&private_key, &ciphertext, Some(&authenticated_data))
                .map_err(|e| PyException::new_err(format!("ECIES error: decryption: {e:?}")))?;
        Ok(plaintext)
    }
}
