use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::bytes_ser_de::{Serializable, Serializer};
use cosmian_findex::{
    parameters::{
        BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KMAC_KEY_LENGTH, KWI_LENGTH, MASTER_KEY_LENGTH, UID_LENGTH,
    },
    EncryptedMultiTable, EncryptedTable, FetchChains, FindexCallbacks, FindexCompact, FindexSearch,
    FindexUpsert, IndexedValue, Keyword, Location, Uids, UpsertData,
};
use tracing::info;

use crate::{
    ffi::{
        core::{
            utils::{
                fetch_callback, get_allocation_size_for_select_chain_request,
                get_serialized_encrypted_entry_table_size_bound,
            },
            FindexUser,
        },
        ErrorCode, FindexFfiError,
    },
    ser_de::{deserialize_fetch_entry_table_results, deserialize_set, serialize_set},
};

impl FindexCallbacks<FindexFfiError, UID_LENGTH> for FindexUser {
    #[tracing::instrument(ret, err)]
    async fn progress(
        &self,
        results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, FindexFfiError> {
        let progress = unwrap_callback!("progress", self, progress);
        let mut serializer = Serializer::new();
        wrapping_callback_ser_de_error_with_context!(
            serializer.write_leb128_u64(results.len() as u64),
            "writing results length for progress callback"
        );
        for (keyword, indexed_values) in results {
            wrapping_callback_ser_de_error_with_context!(
                serializer.write_vec(keyword),
                format!("serializing keyword {keyword:?} for progress callback")
            );
            let indexed_values_bytes = wrapping_callback_ser_de_error_with_context!(
                serialize_set(indexed_values),
                format!("serializing indexed values {indexed_values:?} for progress callback")
            );
            wrapping_callback_ser_de_error_with_context!(
                serializer.write_array(&indexed_values_bytes),
                format!("writing serialized indexed values for progress callback")
            );
        }
        let results = serializer.finalize();
        Ok(progress(results.as_ptr(), results.len() as u32) != 0)
    }

    #[tracing::instrument(ret(Display), err)]
    async fn fetch_all_entry_table_uids(&self) -> Result<Uids<UID_LENGTH>, FindexFfiError> {
        let fetch_all_entry_table_uids = unwrap_callback!(
            "fetch_all_entry_table_uids",
            self,
            fetch_all_entry_table_uids
        );
        let mut allocation_size = 1_000_000 * UID_LENGTH; // about 32MB
        loop {
            let mut output_bytes = vec![0_u8; allocation_size];
            let output_ptr = output_bytes.as_mut_ptr().cast::<u8>();
            let mut output_len = u32::try_from(allocation_size)?;
            let ret = fetch_all_entry_table_uids(output_ptr, &mut output_len);
            if ret == 0 {
                let uids_bytes = unsafe {
                    std::slice::from_raw_parts(output_ptr.cast_const(), output_len as usize)
                };
                return Ok(Uids(wrapping_callback_ser_de_error_with_context!(
                    deserialize_set(uids_bytes),
                    "deserializing uids from fetch all entries callback"
                )));
            } else {
                allocation_size = output_len as usize;
            }
        }
    }

    #[tracing::instrument(fields(entry_table_uids = %entry_table_uids), ret(Display), err)]
    async fn fetch_entry_table(
        &self,
        entry_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedMultiTable<UID_LENGTH>, FindexFfiError> {
        info!("fetch_entry address: {:?}", self.fetch_entry);
        let fetch_entry = unwrap_callback!("fetch_entry", self, fetch_entry);
        info!("fetch_entry address (unwrapped): {:?}", fetch_entry);

        let serialized_uids = wrapping_callback_ser_de_error_with_context!(
            serialize_set(&entry_table_uids.0),
            "serializing entries uids to send to fetch entries callback"
        );
        let res = fetch_callback(
            &serialized_uids,
            get_serialized_encrypted_entry_table_size_bound(
                entry_table_uids.0.len(),
                self.entry_table_number,
            ),
            *fetch_entry,
            "fetch entries",
        )?;

        let encrypted_table = wrapping_callback_ser_de_error_with_context!(
            deserialize_fetch_entry_table_results(&res),
            "deserializing entries from fetch entries callback"
        );
        let encrypted_multi_table = EncryptedMultiTable(encrypted_table);
        info!(
            "results entries: (nb: {}): {encrypted_multi_table}",
            encrypted_multi_table.0.len()
        );

        Ok(encrypted_multi_table)
    }

    #[tracing::instrument(fields(chain_uids = %chain_uids), ret(Display), err)]
    async fn fetch_chain_table(
        &self,
        chain_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexFfiError> {
        info!("fetch_chain address: {:?}", self.fetch_chain);
        let fetch_chain = unwrap_callback!("fetch_chain", self, fetch_chain);
        info!("fetch_chain address (unwrapped): {:?}", fetch_chain);

        let fetch_chain = unwrap_callback!("fetch_chain", self, fetch_chain);
        let serialized_chain_uids = wrapping_callback_ser_de_error_with_context!(
            serialize_set(&chain_uids.0),
            "serializing entries uids to send to fetch entries callback"
        );
        let res = fetch_callback(
            &serialized_chain_uids,
            get_allocation_size_for_select_chain_request(chain_uids.0.len()),
            *fetch_chain,
            "fetch chains",
        )?;
        let encrypted_table = wrapping_callback_ser_de_error_with_context!(
            EncryptedTable::deserialize(&res),
            "deserializing chains from fetch chains callback"
        );
        info!(
            "results chains: (nb: {}): {encrypted_table}",
            encrypted_table.len()
        );
        Ok(encrypted_table)
    }

    #[tracing::instrument(fields(modifications = %modifications), ret(Display), err)]
    async fn upsert_entry_table(
        &self,
        modifications: UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexFfiError> {
        let upsert_entry = unwrap_callback!("upsert_entry", self, upsert_entry);

        // Callback input
        let serialized_upsert_data = wrapping_callback_ser_de_error_with_context!(
            modifications.serialize(),
            "serializing upsert data to send to upsert entries callback"
        );

        // Callback output
        let allocation_size = get_serialized_encrypted_entry_table_size_bound(
            modifications.len(),
            self.entry_table_number,
        );
        let mut serialized_rejected_items = vec![0; allocation_size];
        let mut serialized_rejected_items_len = allocation_size as u32;
        let serialized_rejected_items_ptr = serialized_rejected_items.as_mut_ptr().cast::<u8>();

        // FFI callback
        let error_code = upsert_entry(
            serialized_rejected_items_ptr,
            &mut serialized_rejected_items_len,
            serialized_upsert_data.as_ptr(),
            serialized_upsert_data.len() as u32,
        );

        if error_code != ErrorCode::Success.code() {
            return Err(FindexFfiError::UserCallbackErrorCode {
                callback_name: "upsert entries",
                code: error_code,
            });
        }

        // Set the correct length for the output.
        unsafe {
            serialized_rejected_items.set_len(serialized_rejected_items_len as usize);
        }

        let encrypted_table = wrapping_callback_ser_de_error_with_context!(
            EncryptedTable::deserialize(&serialized_rejected_items),
            "deserializing rejected items from upsert entries callback response"
        );

        Ok(encrypted_table)
    }

    #[tracing::instrument(fields(items = %items), ret, err)]
    async fn insert_chain_table(
        &self,
        items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexFfiError> {
        info!("items: {items}");
        let insert_chain = unwrap_callback!("insert_chain", self, insert_chain);

        // Callback input
        let serialized_items = wrapping_callback_ser_de_error_with_context!(
            items.serialize(),
            "serializing data to send to insert entries callback"
        );

        // FFI callback
        let res = insert_chain(serialized_items.as_ptr(), serialized_items.len() as u32);

        if ErrorCode::Success.code() != res {
            return Err(FindexFfiError::UserCallbackErrorCode {
                callback_name: "insert_chain",
                code: res,
            });
        }

        Ok(())
    }

    #[tracing::instrument(
        fields(
            chain_table_uids_to_remove,
            new_encrypted_entry_table_items,
            new_encrypted_chain_table_items
        ),
        ret,
        err
    )]
    async fn update_lines(
        &self,
        chain_table_uids_to_remove: Uids<UID_LENGTH>,
        new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexFfiError> {
        let update_lines = unwrap_callback!("update_lines", self, update_lines);

        let serialized_chain_table_uids_to_remove = wrapping_callback_ser_de_error_with_context!(
            serialize_set(&chain_table_uids_to_remove.0),
            "serializing chains uids to remove to send to update lines callback"
        );
        let serialized_new_encrypted_entry_table_items = wrapping_callback_ser_de_error_with_context!(
            new_encrypted_entry_table_items.serialize(),
            "serializing new entries to send to update lines callback"
        );
        let serialized_new_encrypted_chain_table_items = wrapping_callback_ser_de_error_with_context!(
            new_encrypted_chain_table_items.serialize(),
            "serializing new chains to send to update lines callback"
        );

        let error_code = update_lines(
            serialized_chain_table_uids_to_remove.as_ptr(),
            u32::try_from(serialized_chain_table_uids_to_remove.len())?,
            serialized_new_encrypted_entry_table_items.as_ptr(),
            u32::try_from(serialized_new_encrypted_entry_table_items.len())?,
            serialized_new_encrypted_chain_table_items.as_ptr(),
            u32::try_from(serialized_new_encrypted_chain_table_items.len())?,
        );

        if error_code != ErrorCode::Success.code() {
            return Err(FindexFfiError::UserCallbackErrorCode {
                callback_name: "update lines",
                code: error_code,
            });
        }

        Ok(())
    }

    #[tracing::instrument(ret, err)]
    async fn list_removed_locations(
        &self,
        locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexFfiError> {
        let list_removed_locations =
            unwrap_callback!("list_removed_locations", self, list_removed_locations);

        let locations_as_bytes = wrapping_callback_ser_de_error_with_context!(
            serialize_set(&locations),
            format!(
                "serializing locations {locations:?} to send to list removed location callback"
            )
        );

        let mut output_bytes = vec![0_u8; locations_as_bytes.len()];
        let output_ptr = output_bytes.as_mut_ptr().cast::<u8>();
        let mut output_len = u32::try_from(locations_as_bytes.len())?;

        let error_code = list_removed_locations(
            output_ptr,
            &mut output_len,
            locations_as_bytes.as_ptr(),
            u32::try_from(locations_as_bytes.len())?,
        );

        if error_code != ErrorCode::Success.code() {
            return Err(FindexFfiError::UserCallbackErrorCode {
                callback_name: "list removed locations",
                code: error_code,
            });
        }

        if output_len == 0 {
            return Ok(HashSet::new());
        }

        let output_locations_bytes =
            unsafe { std::slice::from_raw_parts(output_ptr.cast_const(), output_len as usize) };

        let locations_to_remove = wrapping_callback_ser_de_error_with_context!(
            deserialize_set(output_locations_bytes),
            format!(
                "deserializing locations to remove bytes returned by the list removed location \
                 callback"
            )
        );

        Ok(locations_to_remove)
    }
}

impl FetchChains<UID_LENGTH, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KWI_LENGTH, FindexFfiError>
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
        FindexFfiError,
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
        FindexFfiError,
    > for FindexUser
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
        FindexFfiError,
    > for FindexUser
{
}

