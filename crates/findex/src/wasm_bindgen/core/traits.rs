use std::collections::{HashMap, HashSet};

use cosmian_findex::{
    parameters::{
        DemScheme, KmacKey, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, DEM_KEY_LENGTH, KMAC_KEY_LENGTH,
        KWI_LENGTH, MASTER_KEY_LENGTH, UID_LENGTH,
    },
    EncryptedTable, FetchChains, FindexCallbacks, FindexSearch, FindexUpsert, IndexedValue,
    Keyword, Location, Uid, UpsertData,
};
use js_sys::{Array, Object};

use super::{
    progress_results_to_js,
    utils::{
        encrypted_table_to_js_value, fetch_uids, js_value_to_encrypted_table,
        set_bytes_in_object_property,
    },
    FindexUser,
};
use crate::wasm_bindgen::FindexWasmError;

impl FindexCallbacks<FindexWasmError, UID_LENGTH> for FindexUser {
    async fn progress(
        &self,
        results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, FindexWasmError> {
        let progress = unwrap_callback!(self, progress);
        let results = progress_results_to_js(results)?;
        let output = callback!(progress, results);
        output.as_bool().ok_or_else(|| {
            FindexWasmError::Callback(format!(
                "Progress callback does not return a boolean value: {output:?}"
            ))
        })
    }

    async fn fetch_all_entry_table_uids(
        &self,
    ) -> Result<HashSet<Uid<UID_LENGTH>>, FindexWasmError> {
        todo!("fetch all entry table uids not implemented in WASM")
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexWasmError> {
        let fetch_entry = unwrap_callback!(self, fetch_entry);
        fetch_uids(
            &entry_table_uids.iter().cloned().collect(),
            fetch_entry,
            "fetchEntries",
        )
        .await
    }

    async fn fetch_chain_table(
        &self,
        chain_table_uids: HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexWasmError> {
        let fetch_chain = unwrap_callback!(self, fetch_chain);
        fetch_uids(&chain_table_uids, fetch_chain, "fetchChains").await
    }

    async fn upsert_entry_table(
        &mut self,
        items: UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexWasmError> {
        let upsert_entry = unwrap_callback!(self, upsert_entry);

        // Convert input to JS format
        let inputs = Array::new_with_length(items.len() as u32);
        for (index, (uid, (old_value, new_value))) in items.iter().enumerate() {
            let obj = Object::new();
            set_bytes_in_object_property(&obj, "uid", Some(uid)).map_err(|e| {
                FindexWasmError::Callback(format!(
                    "Cannot convert UID bytes into object property: {e:?}"
                ))
            })?;
            set_bytes_in_object_property(&obj, "oldValue", old_value.as_deref()).map_err(|e| {
                FindexWasmError::Callback(format!(
                    "Cannot convert old value bytes into object property: {e:?}"
                ))
            })?;
            set_bytes_in_object_property(&obj, "newValue", Some(new_value)).map_err(|e| {
                FindexWasmError::Callback(format!(
                    "Cannot convert new value bytes into object property: {e:?}"
                ))
            })?;
            inputs.set(index as u32, obj.into());
        }

        let result = callback!(upsert_entry, inputs);
        js_value_to_encrypted_table(&result, "upsertEntries").map_err(FindexWasmError::from)
    }

    async fn insert_chain_table(
        &mut self,
        items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexWasmError> {
        let insert_chain = unwrap_callback!(self, insert_chain);
        let input = encrypted_table_to_js_value(&items).map_err(|e| {
            FindexWasmError::Callback(format!(
                "Failed to convert Encrypted Table into a JS array: {e:?}"
            ))
        })?;

        callback!(insert_chain, input);
        Ok(())
    }

    fn update_lines(
        &mut self,
        _chain_table_uids_to_remove: HashSet<Uid<UID_LENGTH>>,
        _new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        _new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexWasmError> {
        todo!("update lines not implemented in WASM")
    }

    fn list_removed_locations(
        &self,
        _locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexWasmError> {
        todo!("list removed locations not implemented in WASM")
    }

    #[cfg(feature = "compact_live")]
    fn filter_removed_locations(
        &self,
        _locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexWasmError> {
        todo!("filter removed locations not implemented in WASM")
    }

    #[cfg(feature = "compact_live")]
    async fn delete_chain(
        &mut self,
        _uids: HashSet<Uid<UID_LENGTH>>,
    ) -> Result<(), FindexWasmError> {
        todo!("delete chain not implemented in WASM")
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
        FindexWasmError,
    > for FindexUser
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
        FindexWasmError,
    > for FindexUser
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
        FindexWasmError,
    > for FindexUser
{
}
