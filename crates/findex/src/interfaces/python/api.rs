use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use cosmian_crypto_core::FixedSizeCBytes;
use cosmian_findex::{
    Data, IndexedValue as IndexedValueRust, IndexedValueToKeywordsMap, Keyword, KeywordToDataMap,
    Label, UserKey,
};
use pyo3::prelude::*;
use tokio::runtime::Runtime;

use super::types::ToKeyword;
use crate::{
    db_interfaces::{custom::python::PythonCallbacks, rest::AuthorizationToken},
    interfaces::python::types::{
        Key as KeyPy, Keyword as KeywordPy, Location as LocationPy, ToIndexedValue,
    },
    Configuration, InstantiatedFindex,
};

#[pyclass(unsendable)]
pub struct Findex {
    runtime: Runtime,
    key: UserKey,
    label: Label,
    instance: InstantiatedFindex,
}

#[pymethods]
impl Findex {
    /// Instantiates Findex with an SQLite interface.
    #[staticmethod]
    pub fn new_with_sqlite_interface(
        key: &KeyPy,
        label: String,
        entry_db_path: String,
        chain_db_path: Option<String>,
    ) -> PyResult<Self> {
        let configuration = Configuration::Sqlite(
            entry_db_path.clone(),
            chain_db_path.unwrap_or(entry_db_path),
        );
        let runtime = pyo3_unwrap!(
            tokio::runtime::Runtime::new(),
            "error creating Tokio runtime"
        );
        let instance = pyo3_unwrap!(
            runtime.block_on(InstantiatedFindex::new(configuration)),
            "error instantiating Findex with SQLite backend"
        );
        Ok(Self {
            key: UserKey::try_from_bytes(key.0.to_bytes())
                .expect("the bytes passed represent a correct key"),
            label: Label::from(label.as_str()),
            runtime,
            instance,
        })
    }

    /// Instantiates Findex with a Redis interface.
    #[staticmethod]
    pub fn new_with_redis_interface(
        key: &KeyPy,
        label: String,
        entry_db_url: String,
        chain_db_url: Option<String>,
    ) -> PyResult<Self> {
        let configuration =
            Configuration::Redis(entry_db_url.clone(), chain_db_url.unwrap_or(entry_db_url));
        let runtime = pyo3_unwrap!(
            tokio::runtime::Runtime::new(),
            "error creating Tokio runtime"
        );
        let instance = pyo3_unwrap!(
            runtime.block_on(InstantiatedFindex::new(configuration)),
            "error instantiating Findex with Redis backend"
        );
        Ok(Self {
            key: UserKey::try_from_bytes(key.0.to_bytes())
                .expect("the bytes passed represent a correct key"),
            label: Label::from(label.as_str()),
            runtime,
            instance,
        })
    }

    /// Instantiates Findex with a custom interface.
    #[staticmethod]
    pub fn new_with_custom_interface(
        key: &KeyPy,
        label: String,
        entry_callbacks: PythonCallbacks,
        chain_callbacks: Option<PythonCallbacks>,
    ) -> PyResult<Self> {
        let configuration = Configuration::Python(
            entry_callbacks.clone(),
            chain_callbacks.unwrap_or(entry_callbacks),
        );
        let runtime = pyo3_unwrap!(
            tokio::runtime::Runtime::new(),
            "error creating Tokio runtime"
        );
        let instance = pyo3_unwrap!(
            runtime.block_on(InstantiatedFindex::new(configuration)),
            "error instantiating Findex with Redis backend"
        );
        Ok(Self {
            key: UserKey::try_from_bytes(key.0.to_bytes())
                .expect("the bytes passed represent a correct key"),
            label: Label::from(label.as_str()),
            runtime,
            instance,
        })
    }

    /// Instantiates Findex with a REST backend.
    #[staticmethod]
    pub fn new_with_rest_interface(
        label: String,
        token: String,
        entry_url: String,
        chain_url: Option<String>,
    ) -> PyResult<Self> {
        let token = pyo3_unwrap!(
            AuthorizationToken::from_str(&token),
            "cannot convert token string"
        );
        let runtime = pyo3_unwrap!(
            tokio::runtime::Runtime::new(),
            "error creating Tokio runtime"
        );
        let key = UserKey::try_from_slice(&token.findex_key)
            .expect("the bytes passed represent a correct key");
        let instance = pyo3_unwrap!(
            runtime.block_on(InstantiatedFindex::new(Configuration::Rest(
                token,
                entry_url.clone(),
                chain_url.unwrap_or(entry_url)
            ))),
            "error instantiating Findex with Redis backend"
        );
        Ok(Self {
            key,
            label: Label::from(label.as_str()),
            runtime,
            instance,
        })
    }

    /// Adds the given associations to the index.
    ///
    /// Any subsequent search for such a keyword will result in finding (at
    /// least) the associated indexed values.
    ///
    /// Returns the keywords newly added to the index.
    ///
    /// # Parameters
    ///
    /// - `associations`    : associations to add to the index
    pub fn add(
        &self,
        additions: HashMap<ToIndexedValue, Vec<ToKeyword>>,
    ) -> PyResult<HashSet<KeywordPy>> {
        let new_keywords = pyo3_unwrap!(
            self.runtime.block_on(self.instance.add(
                &self.key,
                &self.label,
                indexed_values_and_keywords_to_rust(additions)
            )),
            "error blocking for addition"
        );

        Ok(new_keywords
            .into_iter()
            .map(KeywordPy)
            .collect::<HashSet<_>>())
    }

    /// Remove the given indexed values for the associated keywords from the
    /// index.
    ///
    /// Any subsequent search for such a keyword will result in finding (at
    /// least) no value listed in one of its association.
    ///
    /// Returns the keywords newly added to the index.
    ///
    /// # Parameters
    ///
    /// - `associations`    : associations to remove from the index
    pub fn delete(
        &self,
        associations: HashMap<ToIndexedValue, Vec<ToKeyword>>,
    ) -> PyResult<HashSet<KeywordPy>> {
        let new_keywords = pyo3_unwrap!(
            self.runtime.block_on(self.instance.delete(
                &self.key,
                &self.label,
                indexed_values_and_keywords_to_rust(associations)
            )),
            "error blocking for addition"
        );

        Ok(new_keywords
            .into_iter()
            .map(KeywordPy)
            .collect::<HashSet<_>>())
    }

    /// Recursively search Findex graphs for `Location` corresponding to the
    /// given `Keyword`.
    ///
    /// Returns: `Locations` found by `Keyword`
    ///
    /// # Parameters
    ///
    /// - `keywords`    : keywords to search in the index
    /// - `interrupt`   : optional callback to process intermediate search
    ///   results.
    #[pyo3(signature = (keywords, interrupt = None))]
    pub fn search(
        &self,
        keywords: Vec<ToKeyword>,
        interrupt: Option<PyObject>,
    ) -> PyResult<HashMap<KeywordPy, Vec<LocationPy>>> {
        let keywords_set: HashSet<Keyword> =
            keywords.into_iter().map(|keyword| keyword.0).collect();

        let interrupt =
            |partial_results: HashMap<Keyword, HashSet<IndexedValueRust<Keyword, Data>>>| async {
                if let Some(interrupt) = &interrupt {
                    let res = Python::with_gil(|py| {
                        let py_results = partial_results
                            .into_iter()
                            .map(|(keyword, locations)| {
                                (
                                    KeywordPy(keyword),
                                    locations
                                        .into_iter()
                                        .map(|indexed_value| match indexed_value {
                                            IndexedValueRust::Data(location) => {
                                                LocationPy(location).into_py(py)
                                            }
                                            IndexedValueRust::Pointer(keyword) => {
                                                KeywordPy(keyword).into_py(py)
                                            }
                                        })
                                        .collect::<Vec<PyObject>>(),
                                )
                            })
                            .collect::<HashMap<_, _>>();

                        let ret = interrupt
                            .call1(py, (py_results,))
                            .expect("the bytes passed represent a correct key");

                        ret.extract(py)
                            .expect("the bytes passed represent a correct key")
                    });

                    Ok(res)
                } else {
                    Ok::<_, String>(false)
                }
            };

        let results = pyo3_unwrap!(
            self.runtime.block_on(self.instance.search(
                &self.key,
                &self.label,
                keywords_set.into(),
                &interrupt
            )),
            "error blocking for search"
        );

        Ok(search_results_to_python(results))
    }

    /// Replace all the previous Index Entry Table UIDs and
    /// values with new ones (UID will be re-hash with the new label and
    /// values will be re-encrypted with a new nonce).
    /// This function will also select a random portion of all the index entries
    /// and recreate the associated chains without removed `Location` from
    /// the main database.
    ///
    /// Parameters
    ///
    /// - `key`                            : key
    /// - `new_key`                        : newly generated key
    /// - `new_label`                      : newly generated label
    /// - `n_compact_to_full` : see below
    ///
    /// `n_compact_to_full`: if you compact the
    /// indexes every night this is the number of days to wait before
    /// being sure that a big portion of the indexes were checked
    /// (see the coupon problem to understand why it's not 100% sure)
    pub fn compact(
        &mut self,
        new_key: &KeyPy,
        new_label: String,
        compacting_rate: f64,
        filter: Option<PyObject>,
    ) -> PyResult<()> {
        let data_filter = |indexed_data: HashSet<Data>| async {
            if let Some(filter) = &filter {
                Python::with_gil(|py| {
                    let py_locations = indexed_data
                        .into_iter()
                        .map(LocationPy)
                        .collect::<HashSet<LocationPy>>();

                    let ret = filter
                        .call1(py, (py_locations,))
                        .expect("the bytes passed represent a correct key");

                    ret.extract(py)
                        .map_err(|e| format!("converting Python remaining locations: {e}"))
                        .map(|remaining_locations: HashSet<LocationPy>| {
                            remaining_locations
                                .into_iter()
                                .map(|py_location| py_location.0)
                                .collect()
                        })
                })
            } else {
                Ok::<_, String>(indexed_data)
            }
        };

        let new_label = Label::from(new_label.as_str());

        pyo3_unwrap!(
            self.runtime.block_on(self.instance.compact(
                &self.key,
                &new_key.0,
                &self.label,
                &new_label,
                compacting_rate,
                &data_filter,
            )),
            "error while blocking for compact"
        );

        self.key = UserKey::try_from_bytes(new_key.0.to_bytes())
            .expect("the bytes passed represent a correct key");
        self.label = new_label;

        Ok(())
    }
}

fn indexed_values_and_keywords_to_rust(
    py_indexed_values_and_keywords: HashMap<ToIndexedValue, Vec<ToKeyword>>,
) -> IndexedValueToKeywordsMap {
    let mut rust_indexed_values_and_keywords =
        HashMap::with_capacity(py_indexed_values_and_keywords.len());
    for (indexed_value, to_keywords) in py_indexed_values_and_keywords {
        let mut keywords = HashSet::with_capacity(to_keywords.len());
        for kw in to_keywords {
            keywords.insert(kw.0);
        }
        rust_indexed_values_and_keywords.insert(indexed_value.0, keywords);
    }
    rust_indexed_values_and_keywords.into()
}

fn search_results_to_python(
    search_results: KeywordToDataMap,
) -> HashMap<KeywordPy, Vec<LocationPy>> {
    search_results
        .into_iter()
        .map(|(keyword, locations)| {
            (
                KeywordPy(keyword),
                locations.into_iter().map(LocationPy).collect::<Vec<_>>(),
            )
        })
        .collect::<HashMap<_, _>>()
}
