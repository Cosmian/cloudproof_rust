use std::hash::Hash;

use cosmian_crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, FixedSizeCBytes, RandomFixedSizeCBytes, SymmetricKey,
};
use cosmian_findex::{
    IndexedValue as IndexedValueRust, Keyword as KeywordRust, Label as LabelRust,
    Location as LocationRust, USER_KEY_LENGTH,
};
use pyo3::{prelude::*, pyclass::CompareOp, types::PyBytes};
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
