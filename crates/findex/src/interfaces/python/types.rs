use std::{collections::HashMap, hash::Hash};

use cosmian_crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, FixedSizeCBytes, RandomFixedSizeCBytes, SymmetricKey,
};
use cosmian_findex::{
    IndexedValue as IndexedValueRust, Keyword as KeywordRust, Label as LabelRust,
    Location as LocationRust, USER_KEY_LENGTH,
};
use pyo3::{prelude::*, pyclass::CompareOp, types::PyBytes};

use crate::backends::rest::{AuthorizationToken as AuthorizationTokenRust, CallbackPrefix};

fn truncate(s: String, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s,
        Some((idx, _)) => format!("{}...", &s[..idx]),
    }
}

fn is_printable_char(c: char) -> bool {
    c.is_alphanumeric() || c.is_ascii_punctuation() || c == ' '
}

#[pyclass(subclass)]
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Keyword(pub(super) KeywordRust);

impl_python_byte!(Keyword, KeywordRust, "Keyword");

#[pyclass(subclass)]
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Location(pub(super) LocationRust);

impl_python_byte!(Location, LocationRust, "Location");

/// Interface to convert python object `Location` and `Keyword` to
/// `IndexedValue` in Rust automatically
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct ToIndexedValue(pub(super) IndexedValueRust<KeywordRust, LocationRust>);

impl<'a> FromPyObject<'a> for ToIndexedValue {
    fn extract(arg: &'a PyAny) -> PyResult<Self> {
        if let Ok(location) = Location::extract(arg) {
            Ok(Self(IndexedValueRust::Data(location.0)))
        } else if let Ok(keyword) = Keyword::extract(arg) {
            Ok(Self(IndexedValueRust::Pointer(keyword.0)))
        } else {
            Err(pyo3::exceptions::PyValueError::new_err(
                "Only `Keyword` and `Location` can be used to index values in Findex",
            ))
        }
    }
}

/// Interface to accept `Keyword` and String in `Upsert`
pub struct ToKeyword(pub(super) KeywordRust);

impl<'a> FromPyObject<'a> for ToKeyword {
    fn extract(arg: &'a PyAny) -> PyResult<Self> {
        if let Ok(keyword) = Keyword::extract(arg) {
            Ok(Self(keyword.0))
        } else if let Ok(str) = String::extract(arg) {
            Ok(Self(KeywordRust::from(str.as_bytes())))
        } else {
            Err(pyo3::exceptions::PyValueError::new_err(
                "Only `Keyword` and `str` can be used to index values in Findex",
            ))
        }
    }
}

/// Additional data used to encrypt the entry table.
#[pyclass]
pub struct Label(pub(super) LabelRust);

#[pymethods]
impl Label {
    /// Initialize a random label.
    ///
    /// Returns:
    ///     Label
    #[staticmethod]
    pub fn random() -> Self {
        let mut rng = CsRng::from_entropy();
        Self(LabelRust::random(&mut rng))
    }

    /// Load from bytes.
    ///
    /// Args:
    ///     label_bytes (bytes)
    ///
    /// Returns:
    ///     Label
    #[staticmethod]
    pub fn from_bytes(label_bytes: Vec<u8>) -> Self {
        Self(LabelRust::from(label_bytes))
    }

    /// Load from a string.
    ///
    /// Args:
    ///     label_str (str)
    ///
    /// Returns:
    ///     Label
    #[staticmethod]
    pub fn from_string(label_str: &str) -> Self {
        Self(LabelRust::from(label_str))
    }

    /// Convert to bytes.
    ///
    /// Returns:
    ///     bytes
    pub fn to_bytes(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.0).into()
    }
}

// Input key used to derive Findex keys.
#[pyclass]
pub struct Key(pub(super) SymmetricKey<USER_KEY_LENGTH>);

#[pymethods]
impl Key {
    /// Initialize a random key.
    ///
    /// Returns:
    ///     MasterKey
    #[staticmethod]
    pub fn random() -> Self {
        let mut rng = CsRng::from_entropy();
        Self(SymmetricKey::<USER_KEY_LENGTH>::new(&mut rng))
    }

    /// Load from bytes.
    ///
    /// Args:
    ///     key_bytes (bytes)
    ///
    /// Returns:
    ///     MasterKey
    #[staticmethod]
    pub fn from_bytes(key_bytes: [u8; USER_KEY_LENGTH]) -> PyResult<Self> {
        Ok(Self(pyo3_unwrap!(
            SymmetricKey::try_from_bytes(key_bytes),
            "Bytes conversion to key error"
        )))
    }

    /// Convert to bytes.
    ///
    /// Returns:
    ///     bytes
    pub fn to_bytes(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.0).into()
    }
}

#[pyclass]
#[derive(Debug)]
pub struct AuthorizationToken(AuthorizationTokenRust);

#[pymethods]
impl AuthorizationToken {
    /// Generates a new random token for the given index. This token holds new
    /// authorization keys for all rights.
    #[staticmethod]
    pub fn random(index_id: String) -> PyResult<Self> {
        let mut rng = CsRng::from_entropy();
        let findex_key = SymmetricKey::new(&mut rng);
        let seeds = (0..4)
            .map(|prefix_id| {
                (
                    CallbackPrefix::try_from(prefix_id).expect("prefix IDs are correct"),
                    SymmetricKey::new(&mut rng),
                )
            })
            .collect();

        Ok(Self(pyo3_unwrap!(
            AuthorizationTokenRust::new(index_id, findex_key, seeds),
            "error creating new token"
        )))
    }

    #[staticmethod]
    pub fn new(
        index_id: String,
        findex_key: &Key,
        fetch_entries_key: Option<&Key>,
        fetch_chains_key: Option<&Key>,
        upsert_entries_key: Option<&Key>,
        insert_chains_key: Option<&Key>,
    ) -> PyResult<Self> {
        let findex_key = pyo3_unwrap!(
            SymmetricKey::try_from_slice(findex_key.0.as_bytes()),
            "cannot parse Findex key from given bytes"
        );

        let mut seeds = HashMap::new();
        if let Some(key) = fetch_entries_key {
            let key = pyo3_unwrap!(
                SymmetricKey::try_from_slice(key.0.as_bytes()),
                "cannot parse fetch entries key from given bytes"
            );
            seeds.insert(CallbackPrefix::FetchEntry, key);
        }
        if let Some(key) = fetch_chains_key {
            let key = pyo3_unwrap!(
                SymmetricKey::try_from_slice(key.0.as_bytes()),
                "cannot parse fetch chains key from given bytes"
            );
            seeds.insert(CallbackPrefix::FetchChain, key);
        }
        if let Some(key) = upsert_entries_key {
            let key = pyo3_unwrap!(
                SymmetricKey::try_from_slice(key.0.as_bytes()),
                "cannot parse upsert entries key from given bytes"
            );
            seeds.insert(CallbackPrefix::Upsert, key);
        }
        if let Some(key) = insert_chains_key {
            let key = pyo3_unwrap!(
                SymmetricKey::try_from_slice(key.0.as_bytes()),
                "cannot parse insert chains key from given bytes"
            );
            seeds.insert(CallbackPrefix::Insert, key);
        }

        Ok(Self(pyo3_unwrap!(
            AuthorizationTokenRust::new(index_id, findex_key, seeds,),
            "error creating new token"
        )))
    }

    /// Generates a new authentication token with the given permissions.
    ///
    /// # Error
    ///
    /// Returns an error if the requested permissions are higher than the ones
    /// associated to this token.
    pub fn generate_reduced_token_string(&self, is_read: bool, is_write: bool) -> PyResult<Self> {
        let mut new_token = self.0.clone();
        pyo3_unwrap!(
            new_token.reduce_permissions(is_read, is_write),
            "when setting permissions"
        );
        Ok(Self(new_token))
    }

    /// Converts to string.
    fn __str__(&self) -> PyResult<String> {
        Ok(self.0.to_string())
    }
}
