use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    num::NonZeroUsize,
    str::FromStr,
};

use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_findex::{
    parameters::{
        DemScheme, KmacKey, BLOCK_LENGTH, DEM_KEY_LENGTH, KMAC_KEY_LENGTH, KWI_LENGTH,
        MASTER_KEY_LENGTH, SECURE_FETCH_CHAINS_BATCH_SIZE, TABLE_WIDTH, UID_LENGTH,
    },
    CallbackError, EncryptedTable, FindexCallbacks, FindexCompact, FindexSearch, FindexUpsert,
    IndexedValue as IndexedValueRust, KeyingMaterial, Keyword, Location, Uid, UpsertData,
};
use futures::executor::block_on;
use pyo3::{
    prelude::*,
    types::{PyBytes, PyDict},
};

use super::py_structs::ToKeyword;
use crate::{
    cloud::{FindexCloud as FindexCloudRust, Token, SIGNATURE_SEED_LENGTH},
    pyo3::py_structs::{
        Keyword as KeywordPy, Label as LabelPy, Location as LocationPy, MasterKey as MasterKeyPy,
        ToIndexedValue,
    },
};

#[derive(Debug)]
pub enum FindexPyo3Error {
    Callback(String),

    ConversionError(String),
}

impl Display for FindexPyo3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Callback(error) => write!(f, "callback error: {error}"),
            Self::ConversionError(error) => write!(f, "conversion error: {error}"),
        }
    }
}
impl std::error::Error for FindexPyo3Error {}
impl CallbackError for FindexPyo3Error {}

#[pyclass]
pub struct InternalFindex {
    fetch_entry: PyObject,
    fetch_chain: PyObject,
    upsert_entry: PyObject,
    insert_chain: PyObject,
    update_lines: PyObject,
    list_removed_locations: PyObject,
    default_progress_callback: PyObject,
    progress_callback: PyObject,
    fetch_all_entry_table_uids: PyObject,
}

impl FindexCallbacks<FindexPyo3Error, UID_LENGTH> for InternalFindex {
    async fn progress(
        &self,
        results: &HashMap<Keyword, HashSet<IndexedValueRust>>,
    ) -> Result<bool, FindexPyo3Error> {
        Python::with_gil(|py| {
            let py_results = results
                .iter()
                .map(|(keyword, locations)| {
                    (
                        KeywordPy(keyword.clone()),
                        locations
                            .iter()
                            .map(|indexed_value| match indexed_value {
                                IndexedValueRust::Location(location) => {
                                    LocationPy(location.clone()).into_py(py)
                                }
                                IndexedValueRust::NextKeyword(keyword) => {
                                    KeywordPy(keyword.clone()).into_py(py)
                                }
                            })
                            .collect::<Vec<PyObject>>(),
                    )
                })
                .collect::<HashMap<_, _>>();

            let ret = self
                .progress_callback
                .call1(py, (py_results,))
                .map_err(|e| FindexPyo3Error::Callback(format!("{e} (progress_callback)")))?;

            ret.extract(py)
                .map_err(|e| FindexPyo3Error::ConversionError(format!("{e} (progress_callback)")))
        })
    }

    async fn fetch_all_entry_table_uids(
        &self,
    ) -> Result<HashSet<Uid<UID_LENGTH>>, FindexPyo3Error> {
        Python::with_gil(|py| {
            let results = self.fetch_all_entry_table_uids.call0(py).map_err(|e| {
                FindexPyo3Error::Callback(format!("{e} (fetch_all_entry_table_uids)"))
            })?;
            let py_result_table: HashSet<[u8; UID_LENGTH]> = results
                .extract(py)
                .map_err(|e| FindexPyo3Error::ConversionError(format!("{e} (fetch_entry)")))?;

            // Convert python result (HashSet<[u8; UID_LENGTH]>) to
            // HashSet<Uid<UID_LENGTH>>
            let entry_table_items = py_result_table
                .into_iter()
                .map(Uid::from)
                .collect::<HashSet<_>>();
            Ok(entry_table_items)
        })
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexPyo3Error> {
        Python::with_gil(|py| {
            let py_entry_uids = entry_table_uids
                .iter()
                .map(|uid| PyBytes::new(py, uid))
                .collect::<Vec<_>>();
            let results = self
                .fetch_entry
                .call1(py, (py_entry_uids,))
                .map_err(|e| FindexPyo3Error::Callback(format!("{e} (fetch_entry)")))?;
            let py_result_table: HashMap<[u8; UID_LENGTH], Vec<u8>> = results
                .extract(py)
                .map_err(|e| FindexPyo3Error::ConversionError(format!("{e} (fetch_entry)")))?;

            // Convert python result (HashMap<[u8; UID_LENGTH], Vec<u8>>) to
            // EncryptedEntryTable<UID_LENGTH>
            let entry_table_items = py_result_table
                .into_iter()
                .map(|(k, v)| (Uid::from(k), v))
                .collect::<HashMap<_, _>>();

            Ok(entry_table_items.into())
        })
    }

    async fn fetch_chain_table(
        &self,
        chain_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexPyo3Error> {
        Python::with_gil(|py| {
            let py_chain_uids = chain_uids
                .iter()
                .map(|uid| PyBytes::new(py, uid))
                .collect::<Vec<_>>();

            let result = self
                .fetch_chain
                .call1(py, (py_chain_uids,))
                .map_err(|e| FindexPyo3Error::Callback(format!("{e} (fetch_chain)")))?;

            let py_result_table: HashMap<[u8; UID_LENGTH], Vec<u8>> = result
                .extract(py)
                .map_err(|e| FindexPyo3Error::ConversionError(format!("{e} (fetch_chain)")))?;

            // Convert python result (HashMap<[u8; UID_LENGTH], Vec<u8>>) to
            // EncryptedTable<UID_LENGTH>
            let chain_table_items = py_result_table
                .into_iter()
                .map(|(k, v)| (Uid::from(k), v))
                .collect::<HashMap<_, _>>();
            Ok(chain_table_items.into())
        })
    }

    async fn upsert_entry_table(
        &mut self,
        items: &UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexPyo3Error> {
        let empty_vec = &vec![];
        Python::with_gil(|py| {
            let py_entry_table = PyDict::new(py);
            for (key, (old_value, new_value)) in items.iter() {
                py_entry_table
                    .set_item(
                        PyBytes::new(py, key),
                        (
                            PyBytes::new(py, old_value.as_ref().unwrap_or(empty_vec)),
                            PyBytes::new(py, new_value),
                        ),
                    )
                    .map_err(|e| FindexPyo3Error::ConversionError(format!("{e} (upsert_entry)")))?;
            }

            let rejected_lines = self
                .upsert_entry
                .call1(py, (py_entry_table,))
                .map_err(|e| FindexPyo3Error::Callback(format!("{e} (upsert_entry)")))?;

            let rejected_lines: HashMap<[u8; UID_LENGTH], Vec<u8>> = rejected_lines
                .extract(py)
                .map_err(|e| FindexPyo3Error::ConversionError(format!("{e} (upsert_entry)")))?;

            let rejected_lines = rejected_lines
                .into_iter()
                .map(|(k, v)| (Uid::from(k), v))
                .collect::<HashMap<_, _>>();

            Ok(rejected_lines.into())
        })
    }

    async fn insert_chain_table(
        &mut self,
        items: &EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexPyo3Error> {
        Python::with_gil(|py| {
            let py_chain_table = PyDict::new(py);
            for (key, value) in items.iter() {
                py_chain_table
                    .set_item(PyBytes::new(py, key), PyBytes::new(py, value))
                    .map_err(|e| FindexPyo3Error::ConversionError(format!("{e} (insert_chain)")))?;
            }
            self.insert_chain
                .call1(py, (py_chain_table,))
                .map_err(|e| FindexPyo3Error::Callback(format!("{e} (insert_chain)")))?;
            Ok(())
        })
    }

    fn update_lines(
        &mut self,
        chain_table_uids_to_remove: HashSet<Uid<UID_LENGTH>>,
        new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexPyo3Error> {
        Python::with_gil(|py| {
            let py_entry_table_items = PyDict::new(py);
            for (key, value) in new_encrypted_entry_table_items.iter() {
                py_entry_table_items
                    .set_item(PyBytes::new(py, key), PyBytes::new(py, value))
                    .map_err(|e| FindexPyo3Error::ConversionError(format!("{e} (update_lines)")))?;
            }

            let py_removed_chain_uids: Vec<&PyBytes> = chain_table_uids_to_remove
                .iter()
                .map(|item| PyBytes::new(py, item))
                .collect();

            let py_chain_table_items = PyDict::new(py);
            for (key, value) in new_encrypted_chain_table_items.iter() {
                py_chain_table_items
                    .set_item(PyBytes::new(py, key), PyBytes::new(py, value))
                    .map_err(|e| FindexPyo3Error::ConversionError(format!("{e} (update_lines)")))?;
            }

            self.update_lines
                .call1(
                    py,
                    (
                        py_removed_chain_uids,
                        py_entry_table_items,
                        py_chain_table_items,
                    ),
                )
                .map_err(|e| FindexPyo3Error::Callback(format!("{e} (update_lines)")))?;

            Ok(())
        })
    }

    fn list_removed_locations(
        &self,
        locations: &HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexPyo3Error> {
        Python::with_gil(|py| {
            let py_locations: Vec<LocationPy> =
                locations.iter().map(|l| LocationPy(l.clone())).collect();

            let result = self
                .list_removed_locations
                .call1(py, (py_locations,))
                .map_err(|e| FindexPyo3Error::Callback(format!("{e} (list_removed_locations)")))?;

            let py_result: Vec<LocationPy> = result.extract(py).map_err(|e| {
                FindexPyo3Error::ConversionError(format!("{e} (list_removed_locations)"))
            })?;

            Ok(py_result.iter().map(|l| l.0.clone()).collect())
        })
    }
}

impl
    FindexUpsert<
        UID_LENGTH,
        BLOCK_LENGTH,
        TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
        FindexPyo3Error,
    > for InternalFindex
{
}

impl
    FindexSearch<
        UID_LENGTH,
        BLOCK_LENGTH,
        TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
        FindexPyo3Error,
    > for InternalFindex
{
}

impl
    FindexCompact<
        UID_LENGTH,
        BLOCK_LENGTH,
        TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
        FindexPyo3Error,
    > for InternalFindex
{
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
    /// - `indexed_values_and_keywords` : map of `IndexedValue` to `Keyword`
    /// - `master_key`                  : Findex master key
    /// - `label`                       : label used to allow versioning
    pub fn upsert_wrapper(
        &mut self,
        indexed_values_and_keywords: HashMap<ToIndexedValue, Vec<ToKeyword>>,
        master_key: &MasterKeyPy,
        label: &LabelPy,
    ) -> PyResult<()> {
        pyo3_unwrap!(
            block_on(self.upsert(
                indexed_values_and_keywords_to_rust(indexed_values_and_keywords),
                &master_key.0,
                &label.0
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
    /// - `keywords`                : keywords to search using Findex
    /// - `master_key`              : user secret key
    /// - `label`                   : public label used in keyword hashing
    /// - `max_results_per_keyword` : maximum number of results to fetch per
    ///   keyword
    /// - `max_depth`               : maximum recursion level allowed
    /// - `fetch_chains_batch_size` : batch size during fetch chain
    /// - `progress_callback`       : optional callback to process intermediate
    ///   search results.
    ///
    /// Returns: List[IndexedValue]
    // use `u32::MAX` for `max_result_per_keyword`
    #[pyo3(signature = (
            keywords, master_key, label,
        max_result_per_keyword = 4_294_967_295,
        max_depth = 100,
        fetch_chains_batch_size = 0,
        progress_callback = None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn search_wrapper(
        &mut self,
        keywords: Vec<&str>,
        master_key: &MasterKeyPy,
        label: &LabelPy,
        max_result_per_keyword: usize,
        max_depth: usize,
        fetch_chains_batch_size: usize,
        progress_callback: Option<PyObject>,
    ) -> PyResult<HashMap<KeywordPy, Vec<LocationPy>>> {
        self.progress_callback = match progress_callback {
            Some(callback) => callback,
            None => self.default_progress_callback.clone(),
        };

        let keywords_set: HashSet<Keyword> = keywords
            .iter()
            .map(|keyword| Keyword::from(*keyword))
            .collect();

        let results = pyo3_unwrap!(
            block_on(
                self.search(
                    &keywords_set,
                    &master_key.0,
                    &label.0,
                    max_result_per_keyword,
                    max_depth,
                    NonZeroUsize::new(fetch_chains_batch_size)
                        .unwrap_or(SECURE_FETCH_CHAINS_BATCH_SIZE),
                    0,
                )
            ),
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
    /// - `num_reindexing_before_full_set` : see below
    /// - `master_key`                     : master key
    /// - `new_master_key`                 : newly generated key
    /// - `new_label`                      : newly generated label
    ///
    /// `num_reindexing_before_full_set`: if you compact the
    /// indexes every night this is the number of days to wait before
    /// being sure that a big portion of the indexes were checked
    /// (see the coupon problem to understand why it's not 100% sure)
    pub fn compact_wrapper(
        &mut self,
        num_reindexing_before_full_set: u32,
        master_key: &MasterKeyPy,
        new_master_key: &MasterKeyPy,
        new_label: &LabelPy,
    ) -> PyResult<()> {
        pyo3_unwrap!(
            block_on(self.compact(
                num_reindexing_before_full_set,
                &master_key.0,
                &new_master_key.0,
                &new_label.0,
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
    /// - `indexed_values_and_keywords` : map of `IndexedValue` to `Keyword`
    /// - `token`                       : Findex token
    /// - `label`                       : label used to allow versioning
    #[staticmethod]
    pub fn upsert(
        indexed_values_and_keywords: HashMap<ToIndexedValue, Vec<ToKeyword>>,
        token: &str,
        label: &LabelPy,
        base_url: Option<String>,
    ) -> PyResult<()> {
        let mut findex = pyo3_unwrap!(FindexCloudRust::new(token, base_url), "error reading token");
        let master_key = findex.token.findex_master_key.clone();

        let future = findex.upsert(
            indexed_values_and_keywords_to_rust(indexed_values_and_keywords),
            &master_key,
            &label.0,
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
    /// - `keywords`                : keywords to search using Findex
    /// - `token`                   : Findex token
    /// - `label`                   : public label used in keyword hashing
    /// - `max_results_per_keyword` : maximum number of results to fetch per
    ///   keyword
    /// - `max_depth`               : maximum recursion level allowed
    /// - `fetch_chains_batch_size` : batch size during fetch chain
    ///
    /// Returns: List[IndexedValue]
    #[staticmethod]
    #[pyo3(signature = (
        keywords,
        token,
        label,
        max_result_per_keyword = 4_294_967_295,
        max_depth = 100,
        fetch_chains_batch_size = 0,
        base_url = None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn search(
        keywords: Vec<&str>,
        token: &str,
        label: &LabelPy,
        max_result_per_keyword: usize,
        max_depth: usize,
        fetch_chains_batch_size: usize,
        base_url: Option<String>,
    ) -> PyResult<HashMap<KeywordPy, Vec<LocationPy>>> {
        let mut findex = pyo3_unwrap!(FindexCloudRust::new(token, base_url), "error reading token");
        let master_key = findex.token.findex_master_key.clone();

        let keywords_set: HashSet<Keyword> = keywords
            .iter()
            .map(|keyword| Keyword::from(*keyword))
            .collect();

        let rt = pyo3_unwrap!(
            tokio::runtime::Runtime::new(),
            "async runtime creation error"
        );

        let results = pyo3_unwrap!(
            rt.block_on(
                findex.search(
                    &keywords_set,
                    &master_key,
                    &label.0,
                    max_result_per_keyword,
                    max_depth,
                    NonZeroUsize::new(fetch_chains_batch_size)
                        .unwrap_or(SECURE_FETCH_CHAINS_BATCH_SIZE),
                    0,
                )
            ),
            "error blocking for search"
        );

        Ok(search_results_to_python(results))
    }

    /// Generate a new Findex Cloud token with reduced permissions
    #[staticmethod]
    pub fn derive_new_token(token: String, search: bool, index: bool) -> PyResult<String> {
        let mut token = pyo3_unwrap!(Token::from_str(&token), "error reading token");

        pyo3_unwrap!(
            token.reduce_permissions(search, index),
            "error reducing token permissions"
        );

        Ok(token.to_string())
    }

    /// Generate a new random Findex Cloud token
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
