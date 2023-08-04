use std::collections::{HashMap, HashSet};

use cosmian_findex::{
    parameters::{
        BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KMAC_KEY_LENGTH, KWI_LENGTH, MASTER_KEY_LENGTH, UID_LENGTH,
    },
    EncryptedMultiTable, EncryptedTable, FetchChains, FindexCallbacks, FindexSearch, FindexUpsert,
    IndexedValue, Keyword, Location, Uids, UpsertData,
};
use js_sys::{Array, Object};

use super::{
    progress_results_to_js,
    utils::{
        encrypted_table_to_js_value, fetch_uids, js_value_to_entry_table_items,
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

    async fn fetch_all_entry_table_uids(&self) -> Result<Uids<UID_LENGTH>, FindexWasmError> {
        Err(FindexWasmError::Callback(
            "fetch all entry table uids not implemented in WASM".to_string(),
        ))
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedMultiTable<UID_LENGTH>, FindexWasmError> {
        log::info!("fetch_entry_table: entry_table_uids: {entry_table_uids}");
        let fetch_entry = unwrap_callback!(self, fetch_entry);
        log::info!("fetch_entry_table: fetch_entry: {fetch_entry:?}");
        let uids = fetch_uids(
            &Uids(entry_table_uids.0.iter().copied().collect()),
            fetch_entry,
            "fetchEntries",
        )
        .await?;
        log::info!("fetch_entry_table: output: {uids}");
        Ok(uids)
    }

    async fn fetch_chain_table(
        &self,
        chain_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexWasmError> {
        log::info!("fetch_chain_table: chain_table_uids: {chain_table_uids}");

        let fetch_chain = unwrap_callback!(self, fetch_chain);
        let chain_table_items = fetch_uids(&chain_table_uids, fetch_chain, "fetchChains").await?;

        // Convert the list of chains to `EncryptedTable`
        let encrypted_table = EncryptedTable::try_from(chain_table_items).map_err(|e| {
            FindexWasmError::Callback(format!(
                "EncryptedTable deserialization failed in fetch_chain_table: {e:?}"
            ))
        })?;
        log::info!("fetch_entry_table: output: {encrypted_table}");
        Ok(encrypted_table)
    }

    async fn upsert_entry_table(
        &self,
        items: UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexWasmError> {
        log::info!("fetch_chain_table: items: {items}");

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
        let fetch_entries_results = js_value_to_entry_table_items(&result, "upsertEntries")
            .map_err(FindexWasmError::from)?;

        // Convert the list of entries to `EncryptedTable`
        let encrypted_table = EncryptedTable::try_from(fetch_entries_results).map_err(|e| {
            FindexWasmError::Callback(format!(
                "EncryptedTable deserialization failed in upsert_entry_table callback: {e:?}"
            ))
        })?;

        log::info!("upsert_entry_table: output: {encrypted_table}");
        Ok(encrypted_table)
    }

    async fn insert_chain_table(
        &self,
        items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexWasmError> {
        log::info!("insert_chain_table: items: {items}");

        let insert_chain = unwrap_callback!(self, insert_chain);
        let input = encrypted_table_to_js_value(&items).map_err(|e| {
            FindexWasmError::Callback(format!(
                "Failed to convert Encrypted Table into a JS array: {e:?}"
            ))
        })?;

        callback!(insert_chain, input);

        log::info!("insert_chain_table: exiting in success");
        Ok(())
    }

    async fn update_lines(
        &self,
        _chain_table_uids_to_remove: Uids<UID_LENGTH>,
        _new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        _new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexWasmError> {
        Err(FindexWasmError::Callback(
            "update lines not implemented in WASM".to_string(),
        ))
    }

    async fn list_removed_locations(
        &self,
        _locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexWasmError> {
        Err(FindexWasmError::Callback(
            "list removed locations not implemented in WASM".to_string(),
        ))
    }

}

impl FetchChains<UID_LENGTH, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KWI_LENGTH, FindexWasmError>
    for FindexUser
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
        FindexWasmError,
    > for FindexUser
{
}
