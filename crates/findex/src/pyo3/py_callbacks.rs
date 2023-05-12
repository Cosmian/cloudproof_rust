use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use cosmian_findex::{
    parameters::{
        DemScheme, KmacKey, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, DEM_KEY_LENGTH, KMAC_KEY_LENGTH,
        KWI_LENGTH, MASTER_KEY_LENGTH, UID_LENGTH,
    },
    CallbackError, EncryptedTable, FetchChains, FindexCallbacks, FindexCompact, FindexSearch,
    FindexUpsert, IndexedValue as IndexedValueRust, Keyword, Location, Uid, UpsertData,
};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyDict},
};

use crate::pyo3::{
    py_api::InternalFindex,
    py_structs::{Keyword as KeywordPy, Location as LocationPy},
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

            // Convert python result (HashSet<[u8; UID_LENGTH]>) to HashSet<Uid<UID_LENGTH>>
            Ok(py_result_table.into_iter().map(Uid::from).collect())
        })
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: HashSet<Uid<UID_LENGTH>>,
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
            Ok(py_result_table
                .into_iter()
                .map(|(k, v)| (Uid::from(k), v))
                .collect())
        })
    }

    async fn fetch_chain_table(
        &self,
        chain_uids: HashSet<Uid<UID_LENGTH>>,
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
            Ok(py_result_table
                .into_iter()
                .map(|(k, v)| (Uid::from(k), v))
                .collect())
        })
    }

    async fn upsert_entry_table(
        &mut self,
        items: UpsertData<UID_LENGTH>,
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

            Ok(rejected_lines
                .into_iter()
                .map(|(k, v)| (Uid::from(k), v))
                .collect())
        })
    }

    async fn insert_chain_table(
        &mut self,
        items: EncryptedTable<UID_LENGTH>,
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
        locations: HashSet<Location>,
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

    #[cfg(feature = "compact_live")]
    fn filter_removed_locations(
        &self,
        _locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexPyo3Error> {
        todo!()
    }

    #[cfg(feature = "compact_live")]
    async fn delete_chain(
        &mut self,
        _uids: HashSet<Uid<UID_LENGTH>>,
    ) -> Result<(), FindexPyo3Error> {
        todo!()
    }
}

impl
    FetchChains<
        UID_LENGTH,
        BLOCK_LENGTH,
        CHAIN_TABLE_WIDTH,
        KWI_LENGTH,
        DEM_KEY_LENGTH,
        DemScheme,
        FindexPyo3Error,
    > for InternalFindex
{
}

impl
    FindexUpsert<
        UID_LENGTH,
        BLOCK_LENGTH,
        CHAIN_TABLE_WIDTH,
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
        CHAIN_TABLE_WIDTH,
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
        CHAIN_TABLE_WIDTH,
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
