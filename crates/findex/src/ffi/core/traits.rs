use std::{
    collections::{HashMap, HashSet},
    ffi::{c_uchar, c_uint},
};

use cosmian_crypto_core::bytes_ser_de::{Serializable, Serializer};
#[cfg(feature = "compact_live")]
use cosmian_findex::FindexLiveCompact;
use cosmian_findex::{
    parameters::{
        DemScheme, KmacKey, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, DEM_KEY_LENGTH, KMAC_KEY_LENGTH,
        KWI_LENGTH, MASTER_KEY_LENGTH, UID_LENGTH,
    },
    EncryptedTable, FetchChains, FindexCallbacks, FindexCompact, FindexSearch, FindexUpsert,
    IndexedValue, Keyword, Location, Uid, UpsertData,
};

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
        Ok(progress(results.as_ptr(), results.len() as c_uint) != 0)
    }

    async fn fetch_all_entry_table_uids(&self) -> Result<HashSet<Uid<UID_LENGTH>>, FindexFfiError> {
        let fetch_all_entry_table_uids = unwrap_callback!(
            "fetch_all_entry_table_uids",
            self,
            fetch_all_entry_table_uids
        );
        let mut allocation_size = 1_000_000 * UID_LENGTH; // about 32MB
        loop {
            let mut output_bytes = vec![0_u8; allocation_size];
            let output_ptr = output_bytes.as_mut_ptr().cast::<c_uchar>();
            let mut output_len = u32::try_from(allocation_size)?;
            let ret = fetch_all_entry_table_uids(output_ptr, &mut output_len);
            if ret == 0 {
                let uids_bytes = unsafe {
                    std::slice::from_raw_parts(output_ptr as *const u8, output_len as usize)
                };
                return Ok(wrapping_callback_ser_de_error_with_context!(
                    deserialize_set(uids_bytes),
                    "deserializing uids from fetch all entries callback"
                ));
            } else {
                allocation_size = output_len as usize;
            }
        }
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: HashSet<Uid<UID_LENGTH>>,
    ) -> Result<Vec<(Uid<UID_LENGTH>, Vec<u8>)>, FindexFfiError> {
        let fetch_entry = unwrap_callback!("fetch_entry", self, fetch_entry);

        let serialized_uids = wrapping_callback_ser_de_error_with_context!(
            serialize_set(&entry_table_uids),
            "serializing entries uids to send to fetch entries callback"
        );
        let res = fetch_callback(
            &serialized_uids,
            get_serialized_encrypted_entry_table_size_bound(
                entry_table_uids.len(),
                self.entry_table_number,
            ),
            *fetch_entry,
            "fetch entries",
        )?;

        let encrypted_table = wrapping_callback_ser_de_error_with_context!(
            deserialize_fetch_entry_table_results(&res),
            "deserializing entries from fetch entries callback"
        );

        Ok(encrypted_table)
    }

    async fn fetch_chain_table(
        &self,
        chain_uids: HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexFfiError> {
        let fetch_chain = unwrap_callback!("fetch_chain", self, fetch_chain);
        let serialized_chain_uids = wrapping_callback_ser_de_error_with_context!(
            serialize_set(&chain_uids),
            "serializing entries uids to send to fetch entries callback"
        );
        let res = fetch_callback(
            &serialized_chain_uids,
            get_allocation_size_for_select_chain_request(chain_uids.len()),
            *fetch_chain,
            "fetch chains",
        )?;
        let encrypted_table = wrapping_callback_ser_de_error_with_context!(
            EncryptedTable::try_from_bytes(&res),
            "deserializing chains from fetch chains callback"
        );
        Ok(encrypted_table)
    }

    async fn upsert_entry_table(
        &mut self,
        modifications: UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexFfiError> {
        let upsert_entry = unwrap_callback!("upsert_entry", self, upsert_entry);

        // Callback input
        let serialized_upsert_data = wrapping_callback_ser_de_error_with_context!(
            modifications.try_to_bytes(),
            "serializing upsert data to send to upsert entries callback"
        );

        // Callback output
        let allocation_size = get_serialized_encrypted_entry_table_size_bound(
            modifications.len(),
            self.entry_table_number,
        );
        let mut serialized_rejected_items = vec![0; allocation_size];
        let mut serialized_rejected_items_len = allocation_size as u32;
        let serialized_rejected_items_ptr =
            serialized_rejected_items.as_mut_ptr().cast::<c_uchar>();

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
            EncryptedTable::try_from_bytes(&serialized_rejected_items),
            "deserializing rejected items from upsert entries callback response"
        );

        Ok(encrypted_table)
    }

    async fn insert_chain_table(
        &mut self,
        items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexFfiError> {
        let insert_chain = unwrap_callback!("insert_chain", self, insert_chain);

        // Callback input
        let serialized_items = wrapping_callback_ser_de_error_with_context!(
            items.try_to_bytes(),
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

    fn update_lines(
        &mut self,
        chain_table_uids_to_remove: HashSet<Uid<UID_LENGTH>>,
        new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexFfiError> {
        let update_lines = unwrap_callback!("update_lines", self, update_lines);

        let serialized_chain_table_uids_to_remove = wrapping_callback_ser_de_error_with_context!(
            serialize_set(&chain_table_uids_to_remove),
            "serializing chains uids to remove to send to update lines callback"
        );
        let serialized_new_encrypted_entry_table_items = wrapping_callback_ser_de_error_with_context!(
            new_encrypted_entry_table_items.try_to_bytes(),
            "serializing new entries to send to update lines callback"
        );
        let serialized_new_encrypted_chain_table_items = wrapping_callback_ser_de_error_with_context!(
            new_encrypted_chain_table_items.try_to_bytes(),
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

    fn list_removed_locations(
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
        let output_ptr = output_bytes.as_mut_ptr().cast::<c_uchar>();
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
            unsafe { std::slice::from_raw_parts(output_ptr as *const u8, output_len as usize) };

        let locations_to_remove = wrapping_callback_ser_de_error_with_context!(
            deserialize_set(output_locations_bytes),
            format!(
                "deserializing locations to remove bytes returned by the list removed location \
                 callback"
            )
        );

        Ok(locations_to_remove)
    }

    #[cfg(feature = "compact_live")]
    fn filter_removed_locations(
        &self,
        locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexFfiError> {
        let filter_removed_locations =
            unwrap_callback!("filter_removed_locations", self, filter_removed_locations);

        let serialized_chain_table_uids_to_remove = wrapping_callback_ser_de_error_with_context!(
            serialize_set(&locations),
            "serializing locations for filter removed locations callback"
        );

        let mut output_bytes = vec![0_u8; serialized_chain_table_uids_to_remove.len()];
        let output_ptr = output_bytes.as_mut_ptr().cast::<c_uchar>();
        let mut output_len = u32::try_from(serialized_chain_table_uids_to_remove.len())?;

        let error_code = filter_removed_locations(
            output_ptr,
            &mut output_len,
            serialized_chain_table_uids_to_remove.as_ptr(),
            u32::try_from(serialized_chain_table_uids_to_remove.len())?,
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
            unsafe { std::slice::from_raw_parts(output_ptr as *const u8, output_len as usize) };

        let locations = wrapping_callback_ser_de_error_with_context!(
            deserialize_set(output_locations_bytes),
            "deserializing existing locations from filter removed locations callback"
        )
        .into_iter()
        .collect();

        Ok(locations)
    }

    #[cfg(feature = "compact_live")]
    async fn delete_chain(&mut self, uids: HashSet<Uid<UID_LENGTH>>) -> Result<(), FindexFfiError> {
        let delete_chain = unwrap_callback!("delete_chain", self, delete_chain);

        // Callback input
        let serialized_items = wrapping_callback_ser_de_error_with_context!(
            serialize_set(&uids),
            "serializing uids for delete chains callback"
        );

        // FFI callback
        let res = delete_chain(serialized_items.as_ptr(), serialized_items.len() as u32);

        if ErrorCode::Success.code() != res {
            return Err(FindexFfiError::UserCallbackErrorCode {
                callback_name: "delete_chain",
                code: res,
            });
        }

        Ok(())
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
        FindexFfiError,
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
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
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
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
        FindexFfiError,
    > for FindexUser
{
}

#[cfg(feature = "compact_live")]
impl
    FindexLiveCompact<
        UID_LENGTH,
        BLOCK_LENGTH,
        CHAIN_TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
        FindexFfiError,
    > for FindexUser
{
    const BATCH_SIZE: usize = 100;
    const NOISE_RATIO: f64 = 0.5;
}
