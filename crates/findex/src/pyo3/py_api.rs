use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_findex::{
    FindexCompact, FindexSearch, FindexUpsert, IndexedValue as IndexedValueRust, KeyingMaterial,
    Keyword, Location,
};
use futures::executor::block_on;
use pyo3::prelude::*;

use super::py_structs::ToKeyword;
use crate::{
    cloud::{FindexCloud as FindexCloudRust, Token, SIGNATURE_SEED_LENGTH},
    pyo3::py_structs::{
        Keyword as KeywordPy, Label as LabelPy, Location as LocationPy, MasterKey as MasterKeyPy,
        ToIndexedValue,
    },
};

#[pyclass]
pub struct InternalFindex {
    pub(super) fetch_entry: PyObject,
    pub(super) fetch_chain: PyObject,
    pub(super) upsert_entry: PyObject,
    pub(super) insert_chain: PyObject,
    pub(super) update_lines: PyObject,
    pub(super) list_removed_locations: PyObject,
    pub(super) default_progress_callback: PyObject,
    pub(super) progress_callback: PyObject,
    pub(super) fetch_all_entry_table_uids: PyObject,
}

#[pymethods]
impl InternalFindex {
    #[new]
    pub fn new(py: Python) -> PyResult<Self> {
        let default_callback: Py<PyAny> = PyModule::from_code(
            py,
            "def default_callback(*args, **kwargs):
                raise NotImplementedError()",
            "",
            "",
        )?
        .getattr("default_callback")?
        .into();

        // `progress_callback` will continue recursion by default
        let default_progress_callback: Py<PyAny> = PyModule::from_code(
            py,
            "def default_progress_callback(*args, **kwargs):
            return True",
            "",
            "",
        )?
        .getattr("default_progress_callback")?
        .into();

        Ok(Self {
            fetch_entry: default_callback.clone(),
            fetch_chain: default_callback.clone(),
            upsert_entry: default_callback.clone(),
            insert_chain: default_callback.clone(),
            update_lines: default_callback.clone(),
            list_removed_locations: default_callback.clone(),
            default_progress_callback: default_progress_callback.clone(),
            progress_callback: default_progress_callback,
            fetch_all_entry_table_uids: default_callback,
        })
    }

    /// Sets the required callbacks to implement [`FindexUpsert`].
    pub fn set_upsert_callbacks(
        &mut self,
        fetch_entry: PyObject,
        upsert_entry: PyObject,
        insert_chain: PyObject,
    ) {
        self.fetch_entry = fetch_entry;
        self.upsert_entry = upsert_entry;
        self.insert_chain = insert_chain
    }

    /// Sets the required callbacks to implement [`FindexSearch`].
    pub fn set_search_callbacks(&mut self, fetch_entry: PyObject, fetch_chain: PyObject) {
        self.fetch_entry = fetch_entry;
        self.fetch_chain = fetch_chain;
    }

    /// Sets the required callbacks to implement [`FindexCompact`].
    pub fn set_compact_callbacks(
        &mut self,
        fetch_entry: PyObject,
        fetch_chain: PyObject,
        update_lines: PyObject,
        list_removed_locations: PyObject,
        fetch_all_entry_table_uids: PyObject,
    ) {
        self.fetch_entry = fetch_entry;
        self.fetch_chain = fetch_chain;
        self.update_lines = update_lines;
        self.list_removed_locations = list_removed_locations;
        self.fetch_all_entry_table_uids = fetch_all_entry_table_uids;
    }

    /// Upserts the given relations between `IndexedValue` and `Keyword` into
    /// Findex tables. After upserting, any search for a `Word` given in the
    /// aforementioned relations will result in finding (at least) the
    /// corresponding `IndexedValue`.
    ///
    /// Parameters
    ///
    /// - `master_key`                  : Findex master key
    /// - `label`                       : label used to allow versioning
    /// - `indexed_values_and_keywords` : map of `IndexedValue` to `Keyword`
    pub fn upsert_wrapper(
        &mut self,
        master_key: &MasterKeyPy,
        label: &LabelPy,
        additions: HashMap<ToIndexedValue, Vec<ToKeyword>>,
        deletions: HashMap<ToIndexedValue, Vec<ToKeyword>>,
    ) -> PyResult<()> {
        pyo3_unwrap!(
            block_on(self.upsert(
                &master_key.0,
                &label.0,
                indexed_values_and_keywords_to_rust(additions),
                indexed_values_and_keywords_to_rust(deletions)
            )),
            "error blocking for upsert"
        );
        Ok(())
    }

    /// Recursively search Findex graphs for `Location` corresponding to the
    /// given `Keyword`.
    ///
    /// Parameters
    ///
    /// - `master_key`              : user secret key
    /// - `label`                   : public label used in keyword hashing
    /// - `keywords`                : keywords to search using Findex
    /// - `progress_callback`       : optional callback to process intermediate
    ///   search results.
    ///
    /// Returns: `Locations` found by `Keyword`
    #[pyo3(signature = (
            master_key, label, keywords,
        progress_callback = None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn search_wrapper(
        &mut self,
        master_key: &MasterKeyPy,
        label: &LabelPy,
        keywords: Vec<ToKeyword>,
        progress_callback: Option<PyObject>,
    ) -> PyResult<HashMap<KeywordPy, Vec<LocationPy>>> {
        self.progress_callback = match progress_callback {
            Some(callback) => callback,
            None => self.default_progress_callback.clone(),
        };

        let keywords_set: HashSet<Keyword> =
            keywords.into_iter().map(|keyword| keyword.0).collect();

        let results = pyo3_unwrap!(
            block_on(self.search(&master_key.0, &label.0, keywords_set)),
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
    /// - `master_key`                     : master key
    /// - `new_master_key`                 : newly generated key
    /// - `new_label`                      : newly generated label
    /// - `num_reindexing_before_full_set` : see below
    ///
    /// `num_reindexing_before_full_set`: if you compact the
    /// indexes every night this is the number of days to wait before
    /// being sure that a big portion of the indexes were checked
    /// (see the coupon problem to understand why it's not 100% sure)
    pub fn compact_wrapper(
        &mut self,
        master_key: &MasterKeyPy,
        new_master_key: &MasterKeyPy,
        new_label: &LabelPy,
        num_reindexing_before_full_set: u32,
    ) -> PyResult<()> {
        pyo3_unwrap!(
            block_on(self.compact(
                &master_key.0,
                &new_master_key.0,
                &new_label.0,
                num_reindexing_before_full_set,
            )),
            "error while blocking for compact"
        );
        Ok(())
    }
}

#[pyclass]
pub struct FindexCloud;

#[pymethods]
impl FindexCloud {
    /// Upserts the given relations between `IndexedValue` and `Keyword` into
    /// Findex tables. After upserting, any search for a `Word` given in the
    /// aforementioned relations will result in finding (at least) the
    /// corresponding `IndexedValue`.
    ///
    /// Parameters
    ///
    /// - `token`                       : Findex token
    /// - `label`                       : label used to allow versioning
    /// - `additions`                   : map of `IndexedValue` to `Keyword`
    /// - `deletions`                   : map of `IndexedValue` to `Keyword`
    /// - `base_url`                    : url of Findex backend (optional)
    #[staticmethod]
    pub fn upsert(
        token: &str,
        label: &LabelPy,
        additions: HashMap<ToIndexedValue, Vec<ToKeyword>>,
        deletions: HashMap<ToIndexedValue, Vec<ToKeyword>>,
        base_url: Option<String>,
    ) -> PyResult<()> {
        let mut findex = pyo3_unwrap!(FindexCloudRust::new(token, base_url), "error reading token");
        let master_key = findex.token.findex_master_key.clone();

        let future = findex.upsert(
            &master_key,
            &label.0,
            indexed_values_and_keywords_to_rust(additions),
            indexed_values_and_keywords_to_rust(deletions),
        );
        let rt = pyo3_unwrap!(
            tokio::runtime::Runtime::new(),
            "async runtime creation error"
        );
        pyo3_unwrap!(rt.block_on(future), "error blocking for upsert");
        Ok(())
    }

    /// Recursively search Findex graphs for `Location` corresponding to the
    /// given `Keyword`.
    ///
    /// Parameters
    ///
    /// - `token`                   : Findex token
    /// - `label`                   : public label used in keyword hashing
    /// - `keywords`                : keywords to search using Findex
    /// - `base_url`                : url of Findex backend (optional)
    ///
    /// Returns: `Locations` found by `Keyword`
    #[staticmethod]
    #[pyo3(signature = (
        token,
        label,
        keywords,
        base_url = None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn search(
        token: &str,
        label: &LabelPy,
        keywords: Vec<ToKeyword>,
        base_url: Option<String>,
    ) -> PyResult<HashMap<KeywordPy, Vec<LocationPy>>> {
        let mut findex = pyo3_unwrap!(FindexCloudRust::new(token, base_url), "error reading token");
        let master_key = findex.token.findex_master_key.clone();

        let keywords_set: HashSet<Keyword> =
            keywords.into_iter().map(|keyword| keyword.0).collect();

        let rt = pyo3_unwrap!(
            tokio::runtime::Runtime::new(),
            "async runtime creation error"
        );

        let results = pyo3_unwrap!(
            rt.block_on(findex.search(&master_key, &label.0, keywords_set)),
            "error blocking for search"
        );

        Ok(search_results_to_python(results))
    }

    /// Generates a new Findex Cloud token with reduced permissions.
    ///
    /// Parameters
    ///
    /// - `token`   : Findex token
    /// - `search`  : add permission to search
    /// - `index`   : add permission to index data
    ///
    /// Returns: updated token
    #[staticmethod]
    pub fn derive_new_token(token: String, search: bool, index: bool) -> PyResult<String> {
        let mut token = pyo3_unwrap!(Token::from_str(&token), "error reading token");

        pyo3_unwrap!(
            token.reduce_permissions(search, index),
            "error reducing token permissions"
        );

        Ok(token.to_string())
    }

    /// Generates a new random Findex Cloud token.
    #[staticmethod]
    pub fn generate_new_token(
        index_id: String,
        fetch_entries_seed: &[u8],
        fetch_chains_seed: &[u8],
        upsert_entries_seed: &[u8],
        insert_chains_seed: &[u8],
    ) -> PyResult<String> {
        let token = pyo3_unwrap!(
            Token::random_findex_master_key(
                index_id,
                uint8slice_to_seed(fetch_entries_seed, "fetch_entries_seed")?,
                uint8slice_to_seed(fetch_chains_seed, "fetch_chains_seed")?,
                uint8slice_to_seed(upsert_entries_seed, "upsert_entries_seed")?,
                uint8slice_to_seed(insert_chains_seed, "insert_chains_seed")?,
            ),
            "error generating new token"
        );

        Ok(token.to_string())
    }
}

/// Conversion helpers from Python types to Rust

fn uint8slice_to_seed(
    seed: &[u8],
    debug_name: &str,
) -> Result<KeyingMaterial<SIGNATURE_SEED_LENGTH>, PyErr> {
    KeyingMaterial::try_from_bytes(seed).map_err(|_| {
        pyo3::exceptions::PyException::new_err(format!(
            "{debug_name} is of wrong size ({SIGNATURE_SEED_LENGTH} expected)",
        ))
    })
}

fn indexed_values_and_keywords_to_rust(
    py_indexed_values_and_keywords: HashMap<ToIndexedValue, Vec<ToKeyword>>,
) -> HashMap<IndexedValueRust, HashSet<Keyword>> {
    let mut rust_indexed_values_and_keywords =
        HashMap::with_capacity(py_indexed_values_and_keywords.len());
    for (indexed_value, to_keywords) in py_indexed_values_and_keywords {
        let mut keywords = HashSet::with_capacity(to_keywords.len());
        for kw in to_keywords {
            keywords.insert(kw.0);
        }
        rust_indexed_values_and_keywords.insert(indexed_value.0, keywords);
    }
    rust_indexed_values_and_keywords
}

fn search_results_to_python(
    search_results: HashMap<Keyword, HashSet<Location>>,
) -> HashMap<KeywordPy, Vec<LocationPy>> {
    search_results
        .iter()
        .map(|(keyword, locations)| {
            (
                KeywordPy(keyword.clone()),
                // Convert Locations to bytes
                locations
                    .iter()
                    .map(|location| LocationPy(location.clone()))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<HashMap<_, _>>()
}
