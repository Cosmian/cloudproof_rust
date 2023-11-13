use std::collections::{HashMap, HashSet};

use cosmian_findex::{EncryptedValue, Token};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyDict},
};

use crate::backends::BackendError;

/// Structure storing the callback functions passed through the Python
/// interface.
///
/// Callback functions needed to be implemented for the Entry and Chain tables
/// given the Findex operation:
/// ```txt
///           +-----------+-----------+-----------+-----------+---------------+
///           | `fetch`   | `upsert`  | `insert`  | `delete`  | `dump_tokens` |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// | search  |  ET + CT  |           |           |           |               |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// | add     |  ET + CT  |     ET    |    CT     |           |               |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// | delete  |  ET + CT  |     ET    |    CT     |           |               |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// | compact |  ET + CT  |           |  ET + CT  |  ET + CT  |       ET      |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// ```
#[derive(Debug, Clone, Default)]
#[pyclass]
pub struct PythonCallbacks {
    pub(crate) fetch: Option<PyObject>,
    pub(crate) upsert: Option<PyObject>,
    pub(crate) insert: Option<PyObject>,
    pub(crate) delete: Option<PyObject>,
    pub(crate) dump_tokens: Option<PyObject>,
}

#[pymethods]
impl PythonCallbacks {
    #[staticmethod]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_fetch(&mut self, callback: PyObject) {
        self.fetch = Some(callback);
    }

    pub fn set_upsert(&mut self, callback: PyObject) {
        self.upsert = Some(callback);
    }

    pub fn set_insert(&mut self, callback: PyObject) {
        self.insert = Some(callback);
    }

    pub fn set_delete(&mut self, callback: PyObject) {
        self.delete = Some(callback);
    }

    pub fn set_dump_tokens(&mut self, callback: PyObject) {
        self.dump_tokens = Some(callback);
    }
}

impl PythonCallbacks {
    pub(crate) async fn fetch<const LENGTH: usize>(
        &self,
        tokens: HashSet<Token>,
    ) -> Result<Vec<(Token, EncryptedValue<LENGTH>)>, BackendError> {
        if let Some(fetch) = &self.fetch {
            Python::with_gil(|py| {
                let py_tokens = tokens
                    .into_iter()
                    .map(|token| PyBytes::new(py, &token))
                    .collect::<Vec<_>>();
                let results = fetch.call1(py, (py_tokens,)).map_err(|e| {
                    BackendError::Python(format!("unwrapping error: {e} (fetch_entry)"))
                })?;
                let results: HashMap<[u8; Token::LENGTH], Vec<u8>> =
                    results.extract(py).map_err(|e| {
                        BackendError::Python(format!(
                            "converting Python results: {e} (fetch_entry)"
                        ))
                    })?;

                results
                    .into_iter()
                    .map(|(k, v)| {
                        EncryptedValue::try_from(v.as_slice())
                            .map_err(BackendError::Findex)
                            .map(|encrypted_value| (Token::from(k), encrypted_value))
                    })
                    .collect()
            })
        } else {
            Err(BackendError::MissingCallback(
                "No attribute fetch is defined for `self`".to_string(),
            ))
        }
    }

    pub(crate) async fn upsert<const LENGTH: usize>(
        &self,
        old_values: HashMap<Token, EncryptedValue<LENGTH>>,
        new_values: HashMap<Token, EncryptedValue<LENGTH>>,
    ) -> Result<HashMap<Token, EncryptedValue<LENGTH>>, BackendError> {
        if let Some(upsert) = &self.upsert {
            Python::with_gil(|py| {
                let py_new_values = PyDict::new(py);
                for (key, value) in &new_values {
                    py_new_values
                        .set_item(
                            PyBytes::new(py, key),
                            PyBytes::new(py, <Vec<u8>>::from(value).as_slice()),
                        )
                        .map_err(|e| {
                            BackendError::Python(format!(
                                "converting new values to Python: {e} (upsert)"
                            ))
                        })?;
                }

                let py_old_values = PyDict::new(py);
                for (key, value) in old_values {
                    py_old_values
                        .set_item(
                            PyBytes::new(py, &key),
                            PyBytes::new(py, <Vec<u8>>::from(&value).as_slice()),
                        )
                        .map_err(|e| {
                            BackendError::Python(format!(
                                "converting old values to Python: {e} (upsert)"
                            ))
                        })?;
                }

                let rejected_lines = upsert
                    .call1(py, (py_old_values, py_new_values))
                    .map_err(|e| BackendError::Python(format!("{e} (upsert)")))?;

                let rejected_lines: HashMap<[u8; Token::LENGTH], Vec<u8>> =
                    rejected_lines.extract(py).map_err(|e| {
                        BackendError::Python(format!(
                            "converting rejections from Python: {e} (upsert)"
                        ))
                    })?;

                rejected_lines
                    .into_iter()
                    .map(|(k, v)| {
                        <EncryptedValue<LENGTH>>::try_from(v.as_slice())
                            .map_err(|e| {
                                BackendError::Python(format!(
                                    "converting rejections from Python: {e} (upsert)"
                                ))
                            })
                            .map(|encrypted_value| (Token::from(k), encrypted_value))
                    })
                    .collect()
            })
        } else {
            Err(BackendError::MissingCallback(
                "No attribute upsert is defined for `self`".to_string(),
            ))
        }
    }

    pub(crate) async fn insert<const LENGTH: usize>(
        &self,
        new_links: HashMap<Token, EncryptedValue<LENGTH>>,
    ) -> Result<(), BackendError> {
        if let Some(insert) = &self.insert {
            Python::with_gil(|py| {
                let py_new_links = PyDict::new(py);
                for (key, value) in &new_links {
                    py_new_links
                        .set_item(
                            PyBytes::new(py, key),
                            PyBytes::new(py, <Vec<u8>>::from(value).as_slice()),
                        )
                        .map_err(|e| {
                            BackendError::Python(format!(
                                "adding new links to the Python dictionary: {e} (insert_chain)"
                            ))
                        })?;
                }
                insert.call1(py, (py_new_links,)).map_err(|e| {
                    BackendError::Python(format!("unwrapping callback error: {e} (insert_chain)"))
                })?;
                Ok(())
            })
        } else {
            Err(BackendError::MissingCallback(
                "No attribute upsert is defined for `self`".to_string(),
            ))
        }
    }

    pub(crate) async fn delete(&self, uids: HashSet<Token>) -> Result<(), BackendError> {
        if let Some(delete) = &self.delete {
            Python::with_gil(|py| {
                let py_uids = uids
                    .iter()
                    .map(|uid| PyBytes::new(py, uid))
                    .collect::<Vec<_>>();
                delete.call1(py, (py_uids,)).map_err(|e| {
                    BackendError::Python(format!("unwrapping callback error: {e} (insert_chain)"))
                })?;
                Ok(())
            })
        } else {
            Err(BackendError::MissingCallback(
                "No attribute upsert is defined for `self`".to_string(),
            ))
        }
    }

    pub(crate) async fn dump_tokens(&self) -> Result<HashSet<Token>, BackendError> {
        if let Some(dump_token) = &self.dump_tokens {
            Python::with_gil(|py| {
                let results = dump_token.call0(py).map_err(|e| {
                    BackendError::Python(format!("unwrapping callback error: {e} (dump_token)"))
                })?;
                let py_result_table: HashSet<[u8; Token::LENGTH]> = results
                    .extract(py)
                    .map_err(|e| BackendError::Python(format!("{e} (fetch_entry)")))?;

                Ok(py_result_table.into_iter().map(Token::from).collect())
            })
        } else {
            Err(BackendError::MissingCallback(
                "No attribute dump_token is defined for `self`".to_string(),
            ))
        }
    }
}
