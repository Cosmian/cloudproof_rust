use cosmian_cover_crypt::{
    abe_policy::AccessPolicy,
    statics::{
        CoverCryptX25519Aes256, EncryptedHeader, MasterSecretKey as MasterSecretKeyRust,
        PublicKey as PublicKeyRust, UserSecretKey as UserSecretKeyRust, DEM,
    },
    CoverCrypt as CoverCryptRust,
};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    symmetric_crypto::{Dem, SymKey},
};
use pyo3::{exceptions::PyTypeError, prelude::*, types::PyBytes};

use crate::pyo3::py_abe_policy::Policy;

// Pyo3 doc on classes
// https://pyo3.rs/v0.16.2/class.html

#[pyclass]
pub struct MasterSecretKey(MasterSecretKeyRust);

impl_key_byte!(MasterSecretKey, MasterSecretKeyRust);

#[pyclass]
pub struct PublicKey(PublicKeyRust);

impl_key_byte!(PublicKey, PublicKeyRust);

#[pyclass]
pub struct UserSecretKey(UserSecretKeyRust);

impl_key_byte!(UserSecretKey, UserSecretKeyRust);

#[pyclass]
pub struct SymmetricKey(<DEM as Dem<{ DEM::KEY_LENGTH }>>::Key);

#[pymethods]
impl SymmetricKey {
    /// Converts key to bytes
    pub fn to_bytes(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.0).into()
    }

    /// Reads key from bytes
    #[staticmethod]
    pub fn from_bytes(key_bytes: [u8; DEM::KEY_LENGTH]) -> PyResult<Self> {
        Ok(Self(<DEM as Dem<{ DEM::KEY_LENGTH }>>::Key::from_bytes(
            key_bytes,
        )))
    }
}

#[pyclass]
pub struct CoverCrypt(CoverCryptX25519Aes256);

#[pymethods]
impl CoverCrypt {
    #[new]
    fn new() -> Self {
        Self(CoverCryptX25519Aes256::default())
    }

    /// Generate the master authority keys for supplied Policy
    ///
    ///  - `policy` : Policy to use to generate the keys
    ///
    /// Parameters:
    ///
    /// Returns: MasterSecretKey
    pub fn generate_master_keys(&self, policy: &Policy) -> PyResult<(MasterSecretKey, PublicKey)> {
        let (msk, pk) = pyo3_unwrap!(
            self.0.generate_master_keys(&policy.0),
            "error generating the master keys"
        );
        Ok((MasterSecretKey(msk), PublicKey(pk)))
    }

    /// Update the master keys according to this new policy.
    ///
    /// When a partition exists in the new policy but not in the master keys,
    /// a new key pair is added to the master keys for that partition.
    /// When a partition exists on the master keys, but not in the new policy,
    /// it is removed from the master keys.
    ///
    ///  - `policy` : Policy to use to generate the keys
    ///  - `msk`    : master secret key
    ///  - `mpk`    : master public key
    pub fn update_master_keys(
        &self,
        policy: &Policy,
        msk: &mut MasterSecretKey,
        pk: &mut PublicKey,
    ) -> PyResult<()> {
        pyo3_unwrap!(
            self.0.update_master_keys(&policy.0, &mut msk.0, &mut pk.0),
            "error updating master keys"
        );
        Ok(())
    }

    /// Generate a user secret key.
    ///
    /// A new user secret key does NOT include to old (i.e. rotated) partitions
    ///
    /// Parameters:
    ///
    /// - `msk`                 : master secret key
    /// - `access_policy_str`   : user access policy
    /// - `policy`              : global policy
    ///
    /// Returns: UserSecretKey
    pub fn generate_user_secret_key(
        &self,
        msk: &MasterSecretKey,
        access_policy_str: &str,
        policy: &Policy,
    ) -> PyResult<UserSecretKey> {
        let access_policy = pyo3_unwrap!(
            AccessPolicy::from_boolean_expression(access_policy_str),
            "error parsing access policy"
        );
        let usk = pyo3_unwrap!(
            self.0
                .generate_user_secret_key(&msk.0, &access_policy, &policy.0),
            "error generating user secret key"
        );

        Ok(UserSecretKey(usk))
    }

    /// Refreshes the user key according to the given master key and access
    /// policy.
    ///
    /// The user key will be granted access to the current partitions, as
    /// determined by its access policy. If `preserve_old_partitions_access`
    /// is set, the user access to rotated partitions will be preserved
    ///
    /// Parameters:
    ///
    /// - `usk`                 : the user key to refresh
    /// - `access_policy`       : the access policy of the user key
    /// - `msk`                 : master secret key
    /// - `policy`              : global policy of the master secret key
    /// - `keep_old_accesses`   : whether access to old partitions (i.e. before
    ///   rotation) should be kept
    pub fn refresh_user_secret_key(
        &self,
        usk: &mut UserSecretKey,
        access_policy_str: &str,
        msk: &MasterSecretKey,
        policy: &Policy,
        keep_old_accesses: bool,
    ) -> PyResult<()> {
        let access_policy = pyo3_unwrap!(
            AccessPolicy::from_boolean_expression(access_policy_str),
            "error parsing access policy"
        );

        pyo3_unwrap!(
            self.0.refresh_user_secret_key(
                &mut usk.0,
                &access_policy,
                &msk.0,
                &policy.0,
                keep_old_accesses,
            ),
            "error refreshing user secret key"
        );

        Ok(())
    }

    /// Encrypts data symmetrically in a block.
    ///
    /// Parameters:
    ///
    /// - `symmetric_key`       : symmetric key
    /// - `plaintext`           : plaintext to encrypt
    /// - `authentication_data` : associated data to be passed to the DEM scheme
    ///
    /// Returns: ciphertext bytes
    pub fn encrypt_symmetric_block(
        &self,
        symmetric_key: &SymmetricKey,
        plaintext: Vec<u8>,
        authentication_data: Option<Vec<u8>>,
        py: Python,
    ) -> PyResult<Py<PyBytes>> {
        let ciphertext = pyo3_unwrap!(
            self.0
                .encrypt(&symmetric_key.0, &plaintext, authentication_data.as_deref(),),
            "error encrypting plaintext"
        );

        Ok(PyBytes::new(py, &ciphertext).into())
    }

    /// Symmetrically Decrypts encrypted data in a block.
    ///
    /// Parameters:
    ///
    /// - `symmetric_key`       : symmetric key
    /// - `ciphertext`          : ciphertext
    /// - `authentication_data` : associated data to be passed to the DEM scheme
    ///
    /// Returns: plaintext bytes
    pub fn decrypt_symmetric_block(
        &self,
        symmetric_key: &SymmetricKey,
        ciphertext: Vec<u8>,
        authentication_data: Option<Vec<u8>>,
        py: Python,
    ) -> PyResult<Py<PyBytes>> {
        let plaintext = pyo3_unwrap!(
            self.0.decrypt(
                &symmetric_key.0,
                &ciphertext,
                authentication_data.as_deref(),
            ),
            "error decrypting plaintext"
        );

        Ok(PyBytes::new(py, &plaintext).into())
    }

    /// Generates an encrypted header. A header contains the following elements:
    ///
    /// - `encapsulation_size`  : the size of the symmetric key encapsulation
    ///   (u32)
    /// - `encapsulation`       : symmetric key encapsulation using CoverCrypt
    /// - `encrypted_metadata`  : Optional metadata encrypted using the DEM
    ///
    /// Parameters:
    ///
    /// - `policy`              : global policy
    /// - `access_policy_str`   : access policy
    /// - `public_key`          : CoverCrypt public key
    /// - `header_metadata`     : additional data to encrypt with the header
    /// - `authentication_data`  : authentication data to use in symmetric
    ///   encryption
    ///
    /// Returns: (SymmetricKey, ciphertext bytes)
    pub fn encrypt_header(
        &self,
        policy: &Policy,
        access_policy_str: &str,
        public_key: &PublicKey,
        header_metadata: Option<Vec<u8>>,
        authentication_data: Option<Vec<u8>>,
        py: Python,
    ) -> PyResult<(SymmetricKey, Py<PyBytes>)> {
        let access_policy = pyo3_unwrap!(
            AccessPolicy::from_boolean_expression(access_policy_str),
            "error parsing access policy"
        );

        let (symmetric_key, encrypted_header) = pyo3_unwrap!(
            EncryptedHeader::generate(
                &self.0,
                &policy.0,
                &public_key.0,
                &access_policy,
                header_metadata.as_deref(),
                authentication_data.as_deref(),
            ),
            "error encrypting CoverCrypt header"
        );

        Ok((
            SymmetricKey(symmetric_key),
            PyBytes::new(
                py,
                &pyo3_unwrap!(
                    encrypted_header.try_to_bytes(),
                    "error serializing CoverCrypt header"
                ),
            )
            .into(),
        ))
    }

    /// Decrypts the given header bytes using a user decryption key.
    ///
    /// Parameters:
    ///
    /// - `usk`                     : user secret key
    /// - `encrypted_header_bytes`  : encrypted header bytes
    /// - `authentication_data`     : authentication data to use in symmetric
    ///   decryption
    ///
    /// Returns: (SymmetricKey, header metadata bytes)
    pub fn decrypt_header(
        &self,
        usk: &UserSecretKey,
        encrypted_header_bytes: Vec<u8>,
        authentication_data: Option<Vec<u8>>,
        py: Python,
    ) -> PyResult<(SymmetricKey, Py<PyBytes>)> {
        let encrypted_header = pyo3_unwrap!(
            EncryptedHeader::try_from_bytes(&encrypted_header_bytes),
            "error deserializing encrypted header"
        );

        let cleartext_header = pyo3_unwrap!(
            encrypted_header.decrypt(&self.0, &usk.0, authentication_data.as_deref()),
            "error decrypting header"
        );

        Ok((
            SymmetricKey(cleartext_header.symmetric_key),
            PyBytes::new(py, &cleartext_header.metadata).into(),
        ))
    }

    /// Hybrid encryption. Concatenates the encrypted header and the symmetric
    /// ciphertext.
    ///
    /// Parameters:
    ///
    /// - `policy`              : global policy
    /// - `access_policy_str`   : access policy
    /// - `pk`                  : CoverCrypt public key
    /// - `plaintext`           : plaintext to encrypt using the DEM
    /// - `header_metadata`     : additional data to symmetrically encrypt in
    ///   the header
    /// - `authentication_data` : authentication data to use in symmetric
    ///   encryptions
    ///
    /// Returns: ciphertext bytes
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt(
        &self,
        policy: &Policy,
        access_policy_str: &str,
        pk: &PublicKey,
        plaintext: Vec<u8>,
        header_metadata: Option<Vec<u8>>,
        authentication_data: Option<Vec<u8>>,
        py: Python,
    ) -> PyResult<Py<PyBytes>> {
        let access_policy = AccessPolicy::from_boolean_expression(access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        let (symmetric_key, encrypted_header) = pyo3_unwrap!(
            EncryptedHeader::generate(
                &self.0,
                &policy.0,
                &pk.0,
                &access_policy,
                header_metadata.as_deref(),
                authentication_data.as_deref(),
            ),
            "error encrypting CoverCrypt header"
        );

        let ciphertext = pyo3_unwrap!(
            self.0
                .encrypt(&symmetric_key, &plaintext, authentication_data.as_deref()),
            "error encrypting plaintext"
        );

        // Encrypted header and ciphertext are concatenated.
        let mut ser = Serializer::with_capacity(encrypted_header.length() + ciphertext.len());
        pyo3_unwrap!(
            encrypted_header.write(&mut ser),
            "error serializing CoverCrypt header"
        );
        pyo3_unwrap!(ser.write_array(&ciphertext), "error serializing ciphertext");

        Ok(PyBytes::new(py, &ser.finalize()).into())
    }

    /// Hybrid decryption.
    ///
    /// Parameters:
    ///
    /// - `usk`                 : user secret key
    /// - `encrypted_bytes`     : encrypted header || symmetric ciphertext
    /// - `authentication_data` : authentication data to use in symmetric
    ///   decryptions
    ///
    ///  Returns: (plaintext bytes, header metadata bytes)
    pub fn decrypt(
        &self,
        usk: &UserSecretKey,
        encrypted_bytes: Vec<u8>,
        authentication_data: Option<Vec<u8>>,
        py: Python,
    ) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
        let mut de = Deserializer::new(encrypted_bytes.as_slice());
        let header = pyo3_unwrap!(
            // this will read the exact header size
            EncryptedHeader::read(&mut de),
            "error deserializing encrypted header"
        );
        // the rest is the symmetric ciphertext
        let ciphertext = de.finalize();

        let cleartext_header = pyo3_unwrap!(
            header.decrypt(&self.0, &usk.0, authentication_data.as_deref()),
            "error decrypting CoverCrypt header"
        );

        let plaintext = pyo3_unwrap!(
            self.0.decrypt(
                &cleartext_header.symmetric_key,
                ciphertext.as_slice(),
                authentication_data.as_deref(),
            ),
            "error decrypting ciphertext"
        );

        Ok((
            PyBytes::new(py, &plaintext).into(),
            PyBytes::new(py, &cleartext_header.metadata).into(),
        ))
    }
}
