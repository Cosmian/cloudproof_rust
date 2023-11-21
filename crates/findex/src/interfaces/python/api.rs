use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use cosmian_findex::{
    IndexedValue as IndexedValueRust, IndexedValueToKeywordsMap, Keyword, KeywordToDataMap,
    Location,
};
use pyo3::prelude::*;
use tokio::runtime::Runtime;

use super::types::ToKeyword;
use crate::{
    backends::{custom::python::PythonCallbacks, rest::AuthorizationToken},
    interfaces::python::types::{
        Key as KeyPy, Keyword as KeywordPy, Label as LabelPy, Location as LocationPy,
        ToIndexedValue,
    },
    BackendConfiguration, InstantiatedFindex,
};

#[pyclass(unsendable)]
pub struct Findex {
    runtime: Runtime,
    instance: InstantiatedFindex,
}

#[pymethods]
impl Findex {
    /// Instantiates Findex with a SQLite as backend.
    #[staticmethod]
    pub fn new_with_sqlite_backend(entry_db_path: String, chain_db_path: String) -> PyResult<Self> {
        let configuration = BackendConfiguration::Sqlite(entry_db_path, chain_db_path);
        let runtime = pyo3_unwrap!(
            tokio::runtime::Runtime::new(),
            "error creating Tokio runtime"
        );
        let instance = pyo3_unwrap!(
            runtime.block_on(InstantiatedFindex::new(configuration)),
            "error instantiating Findex with SQLite backend"
        );
        Ok(Self { runtime, instance })
    }

    /// Instantiates Findex with a Redis as backend.
    #[staticmethod]
    pub fn new_with_redis_backend(entry_db_url: String, chain_db_url: String) -> PyResult<Self> {
        let configuration = BackendConfiguration::Redis(entry_db_url, chain_db_url);
        let runtime = pyo3_unwrap!(
            tokio::runtime::Runtime::new(),
            "error creating Tokio runtime"
        );
        let instance = pyo3_unwrap!(
            runtime.block_on(InstantiatedFindex::new(configuration)),
            "error instantiating Findex with Redis backend"
        );
        Ok(Self { runtime, instance })
    }

    /// Instantiates Findex with a custom backend.
    #[staticmethod]
    pub fn new_with_custom_backend(
        entry_callbacks: PythonCallbacks,
        chain_callbacks: PythonCallbacks,
    ) -> PyResult<Self> {
        let configuration = BackendConfiguration::Python(entry_callbacks, chain_callbacks);
        let runtime = pyo3_unwrap!(
            tokio::runtime::Runtime::new(),
            "error creating Tokio runtime"
        );
        let instance = pyo3_unwrap!(
            runtime.block_on(InstantiatedFindex::new(configuration)),
            "error instantiating Findex with Redis backend"
        );
        Ok(Self { runtime, instance })
    }

    /// Instantiates Findex with a REST backend.
    #[staticmethod]
    pub fn new_with_rest_backend(token: String, url: String) -> PyResult<Self> {
        let token = pyo3_unwrap!(
            AuthorizationToken::from_str(&token),
            "cannot convert token string"
        );
        let runtime = pyo3_unwrap!(
            tokio::runtime::Runtime::new(),
            "error creating Tokio runtime"
        );
        let instance = pyo3_unwrap!(
            runtime.block_on(InstantiatedFindex::new(BackendConfiguration::Rest(
                token, url
            ))),
            "error instantiating Findex with Redis backend"
        );
        Ok(Self { runtime, instance })
    }

    /// Adds the given indexed values for the associated keywords to the index.
    ///
    /// Any subsequent search for such a keyword will result in finding (at
    /// least) the corresponding indexed values.
    ///
    /// Returns the keywords newly added to the index.
    ///
    /// Parameters
    ///
    /// - `key`                         : Findex key
    /// - `label`                       : label used to allow versioning
    /// - `indexed_values_and_keywords` : map of `IndexedValue` to `Keyword`
    pub fn add(
        &self,
        key: &KeyPy,
        label: &LabelPy,
        additions: HashMap<ToIndexedValue, Vec<ToKeyword>>,
    ) -> PyResult<HashSet<KeywordPy>> {
        let new_keywords = pyo3_unwrap!(
            self.runtime.block_on(self.instance.add(
                &key.0,
                &label.0,
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
    /// Any subsequent search for such a keyword will not result in finding (at
    /// least) the corresponding indexed values.
    ///
    /// Returns the keywords newly added to the index.
    ///
    /// Parameters
    ///
    /// - `key`         : Findex key
    /// - `label`       : label used to allow versioning
    /// - `deletions`   : map of indexed values to the set of keyword
    pub fn delete(
        &self,
        key: &KeyPy,
        label: &LabelPy,
        deletions: HashMap<ToIndexedValue, Vec<ToKeyword>>,
    ) -> PyResult<HashSet<KeywordPy>> {
        let new_keywords = pyo3_unwrap!(
            self.runtime.block_on(self.instance.delete(
                &key.0,
                &label.0,
                indexed_values_and_keywords_to_rust(deletions)
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
    /// Parameters
    ///
    /// - `key`                     : Findex key
    /// - `label`                   : Findex label
    /// - `keywords`                : keywords to search in the index
    /// - `interrupt`               : optional callback to process intermediate
    ///   search results.
    ///
    /// Returns: `Locations` found by `Keyword`
    #[pyo3(signature = (
        key, label, keywords,
        interrupt = None
    ))]
    pub fn search(
        &self,
        key: &KeyPy,
        label: &LabelPy,
        keywords: Vec<ToKeyword>,
        interrupt: Option<PyObject>,
    ) -> PyResult<HashMap<KeywordPy, Vec<LocationPy>>> {
        let keywords_set: HashSet<Keyword> =
            keywords.into_iter().map(|keyword| keyword.0).collect();

        let interrupt = |partial_results: HashMap<
            Keyword,
            HashSet<IndexedValueRust<Keyword, Location>>,
        >| async {
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

                    let ret = interrupt.call1(py, (py_results,)).unwrap();

                    ret.extract(py).unwrap()
                });

                Ok(res)
            } else {
                Ok::<_, String>(false)
            }
        };

        let results = pyo3_unwrap!(
            self.runtime.block_on(self.instance.search(
                &key.0,
                &label.0,
                keywords_set.into(),
                &interrupt
            )),
            "error blocking for search"
        );

        Ok(search_results_to_python(results))
    }

    /*/// Replace all the previous Index Entry Table UIDs and
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
    /// - `num_reindexing_before_full_set` : see below
    ///
    /// `num_reindexing_before_full_set`: if you compact the
    /// indexes every night this is the number of days to wait before
    /// being sure that a big portion of the indexes were checked
    /// (see the coupon problem to understand why it's not 100% sure)
    pub fn compact(
        &self,
        key: &KeyPy,
        new_key: &KeyPy,
        new_label: &LabelPy,
        num_reindexing_before_full_set: u32,
    ) -> PyResult<()> {
        let findex: FindexRust = match self.backend {
            FindexBackends::Redis(et, ed) => {
                Findex::<BackendError, _, _>::new(EntryTable::setup(et), ChainTable::setup(ed))
            }
            FindexBackends::SQLite(et, ed) => {
                Findex::<BackendError, _, _>::new(EntryTable::setup(et), ChainTable::setup(ed))
            }
        };

        pyo3_unwrap!(
            block_on(findex.compact(
                &key.0,
                &new_key.0,
                &new_label.0,
                num_reindexing_before_full_set,
            )),
            "error while blocking for compact"
        );
        Ok(())
    }*/
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
