//! Defines the Findex FFI API.

use std::{
    collections::HashSet,
    convert::TryFrom,
    num::NonZeroU32,
    os::raw::{c_char, c_int},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use cosmian_crypto_core::bytes_ser_de::{Serializable, Serializer};
use cosmian_ffi_utils::{
    error::{h_get_error, set_last_error, FfiError},
    ffi_read_bytes, ffi_read_string, ffi_unwrap, ffi_write_bytes,
};
#[cfg(feature = "compact_live")]
use cosmian_findex::FindexLiveCompact;
use cosmian_findex::{
    parameters::{
        DemScheme, KmacKey, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, DEM_KEY_LENGTH, KMAC_KEY_LENGTH,
        KWI_LENGTH, MASTER_KEY_LENGTH, UID_LENGTH,
    },
    CallbackError, Error as FindexError, FindexCompact, FindexSearch, FindexUpsert, KeyingMaterial,
    Keyword, Label,
};

use super::error::ToErrorCode;
#[cfg(feature = "cloud")]
use crate::cloud::{FindexCloud, Token};
#[cfg(feature = "compact_live")]
use crate::ffi::core::DeleteChainCallback;
use crate::{
    ffi::core::{
        utils::parse_indexed_values, FetchAllEntryTableUidsCallback, FetchChainTableCallback,
        FetchEntryTableCallback, FindexUser, InsertChainTableCallback,
        ListRemovedLocationsCallback, ProgressCallback, UpdateLinesCallback,
        UpsertEntryTableCallback,
    },
    ser_de::serialize_set,
};

/// Re-export the `cosmian_ffi` `h_get_error` function to clients with the old
/// `get_last_error` name The `h_get_error` is available inside the final lib
/// (but tools like ffigen seems to not parse it…) Maybe we can find a solution
/// by changing the function name inside the clients.
///
/// # Safety
///
/// It's unsafe.
#[no_mangle]
pub unsafe extern "C" fn get_last_error(error_ptr: *mut c_char, error_len: *mut c_int) -> c_int {
    h_get_error(error_ptr, error_len)
}

#[no_mangle]
/// Recursively searches Findex graphs for values indexed by the given keywords.
///
/// # Serialization
///
/// Le output is serialized as follows:
///
/// `LEB128(n_keywords) || LEB128(keyword_1)
///     || keyword_1 || LEB128(n_associated_results)
///     || LEB128(associated_result_1) || associated_result_1
///     || ...`
///
/// # Parameters
///
/// - `search_results`          : (output) search result
/// - `master_key`              : master key
/// - `label`                   : public information used to derive UIDs
/// - `keywords`                : `serde` serialized list of base64 keywords
/// - `progress_callback`       : callback used to retrieve intermediate results
///   and transmit user interrupt
/// - `fetch_entry_callback`    : callback used to fetch the Entry Table
/// - `fetch_chain_callback`    : callback used to fetch the Chain Table
///
/// # Safety
///
/// Cannot be safe since using FFI.
pub unsafe extern "C" fn h_search(
    search_results_ptr: *mut c_char,
    search_results_len: *mut c_int,
    master_key_ptr: *const c_char,
    master_key_len: c_int,
    label_ptr: *const u8,
    label_len: c_int,
    keywords_ptr: *const c_char,
    progress_callback: ProgressCallback,
    fetch_entry_callback: FetchEntryTableCallback,
    fetch_chain_callback: FetchChainTableCallback,
) -> c_int {
    let master_key_bytes = ffi_read_bytes!("master key", master_key_ptr, master_key_len);
    let master_key = ffi_unwrap!(
        KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(master_key_bytes),
        "error deserializing master secret key"
    );

    let findex = FindexUser {
        progress: Some(progress_callback),
        fetch_all_entry_table_uids: None,
        fetch_entry: Some(fetch_entry_callback),
        fetch_chain: Some(fetch_chain_callback),
        upsert_entry: None,
        insert_chain: None,
        #[cfg(feature = "compact_live")]
        delete_chain: None,
        update_lines: None,
        list_removed_locations: None,
        #[cfg(feature = "compact_live")]
        filter_removed_locations: None,
    };

    ffi_search(
        findex,
        &master_key,
        search_results_ptr,
        search_results_len,
        label_ptr,
        label_len,
        keywords_ptr,
    )
}

#[no_mangle]
/// Index the given values for the given keywords. After upserting, any
/// search for such a keyword will result in finding (at least) the
/// corresponding value.
///
/// # Serialization
///
/// The list of values to index for the associated keywords should be serialized
/// as follows:
///
/// `LEB128(n_values) || serialized_value_1
///     || LEB128(n_associated_keywords) || serialized_keyword_1 || ...`
///
/// where values serialized as follows:
///
/// `LEB128(value_bytes.len() + 1) || base64(prefix || value_bytes)`
///
/// with `prefix` being `l` for a `Location` and `w` for a `NextKeyword`, and
/// where keywords are serialized as follows:
///
/// `LEB128(keyword_bytes.len()) || base64(keyword_bytes)`
///
/// # Parameters
///
/// - `master_key`      : Findex master key
/// - `label`           : additional information used to derive Entry Table UIDs
/// TODO (TBZ): explain the serialization in the doc
/// - `additions`       : serialized list of new indexed values
/// - `deletions`       : serialized list of removed indexed values
/// - `fetch_entry`     : callback used to fetch the Entry Table
/// - `upsert_entry`    : callback used to upsert lines in the Entry Table
/// - `insert_chain`    : callback used to insert lines in the Chain Table
///
/// # Safety
///
/// Cannot be safe since using FFI.
pub unsafe extern "C" fn h_upsert(
    master_key_ptr: *const u8,
    master_key_len: c_int,
    label_ptr: *const u8,
    label_len: c_int,
    additions_ptr: *const c_char,
    deletions_ptr: *const c_char,
    fetch_entry: FetchEntryTableCallback,
    upsert_entry: UpsertEntryTableCallback,
    insert_chain: InsertChainTableCallback,
) -> c_int {
    let master_key_bytes = ffi_read_bytes!("master key", master_key_ptr, master_key_len);
    let master_key = ffi_unwrap!(
        KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(master_key_bytes),
        "error re-serializing master secret key"
    );

    let findex = FindexUser {
        progress: None,
        fetch_all_entry_table_uids: None,
        fetch_entry: Some(fetch_entry),
        fetch_chain: None,
        upsert_entry: Some(upsert_entry),
        insert_chain: Some(insert_chain),
        #[cfg(feature = "compact_live")]
        delete_chain: None,
        update_lines: None,
        list_removed_locations: None,
        #[cfg(feature = "compact_live")]
        filter_removed_locations: None,
    };

    ffi_upsert(
        findex,
        &master_key,
        label_ptr,
        label_len,
        additions_ptr,
        deletions_ptr,
    )
}

#[no_mangle]
/// Replaces all the Index Entry Table UIDs and values. New UIDs are derived
/// using the given label and the KMAC key derived from the new master key. The
/// values are decrypted using the DEM key derived from the master key and
/// re-encrypted using the DEM key derived from the new master key.
///
/// Randomly selects index entries and recompact their associated chains. Chains
/// indexing no existing location are removed. Others are recomputed from a new
/// keying material. This removes unneeded paddings. New UIDs are derived for
/// the chain and values are re-encrypted using a DEM key derived from the new
/// keying material.
///
/// # Parameters
///
/// - `old_master_key`                  : old Findex master key
/// - `new_master_key`                  : new Findex master key
/// - `new_label`                       : public information used to derive UIDs
/// - `num_reindexing_before_full_set`  : number of compact operation needed to
///   compact all the Chain Table
/// - `fetch_entry`                     : callback used to fetch the Entry Table
/// - `fetch_chain`                     : callback used to fetch the Chain Table
/// - `update_lines`                    : callback used to update lines in both
///   tables
/// - `list_removed_locations`          : callback used to list removed
///   locations among the ones given
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[cfg(feature = "compact_live")]
pub unsafe extern "C" fn h_live_compact(
    master_key_ptr: *const u8,
    master_key_len: c_int,
    num_reindexing_before_full_set: c_int,
    fetch_all_entry_table_uids: FetchAllEntryTableUidsCallback,
    fetch_entry: FetchEntryTableCallback,
    fetch_chain: FetchChainTableCallback,
    delete_chain: DeleteChainCallback,
    filter_removed_locations: ListRemovedLocationsCallback,
) -> c_int {
    let num_reindexing_before_full_set = ffi_unwrap!(
        u32::try_from(num_reindexing_before_full_set)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or_else(|| format!(
                "num_reindexing_before_full_set ({num_reindexing_before_full_set}) should be a \
                 non-zero positive integer."
            )),
        "error converting num_reindexing_before_full_set"
    );

    let master_key_bytes = ffi_read_bytes!("master key", master_key_ptr, master_key_len);
    let master_key = ffi_unwrap!(
        KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(master_key_bytes),
        "error deserializing master secret key"
    );

    let mut findex = FindexUser {
        progress: None,
        fetch_all_entry_table_uids: Some(fetch_all_entry_table_uids),
        fetch_entry: Some(fetch_entry),
        fetch_chain: Some(fetch_chain),
        upsert_entry: None,
        insert_chain: None,
        delete_chain: Some(delete_chain),
        update_lines: None,
        list_removed_locations: None,
        filter_removed_locations: Some(filter_removed_locations),
    };

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    ffi_unwrap!(
        rt.block_on(findex.live_compact(&master_key, num_reindexing_before_full_set.into(),)),
        "error waiting for the compact operation to return"
    );

    0
}

#[no_mangle]
/// Replaces all the Index Entry Table UIDs and values. New UIDs are derived
/// using the given label and the KMAC key derived from the new master key. The
/// values are decrypted using the DEM key derived from the master key and
/// re-encrypted using the DEM key derived from the new master key.
///
/// Randomly selects index entries and recompact their associated chains. Chains
/// indexing no existing location are removed. Others are recomputed from a new
/// keying material. This removes unneeded paddings. New UIDs are derived for
/// the chain and values are re-encrypted using a DEM key derived from the new
/// keying material.
///
/// # Parameters
///
/// - `old_master_key`                  : old Findex master key
/// - `new_master_key`                  : new Findex master key
/// - `new_label`                       : public information used to derive UIDs
/// - `num_reindexing_before_full_set`  : number of compact operation needed to
///   compact all the Chain Table
/// - `fetch_entry`                     : callback used to fetch the Entry Table
/// - `fetch_chain`                     : callback used to fetch the Chain Table
/// - `update_lines`                    : callback used to update lines in both
///   tables
/// - `list_removed_locations`          : callback used to list removed
///   locations among the ones given
///
/// # Safety
///
/// Cannot be safe since using FFI.
pub unsafe extern "C" fn h_compact(
    old_master_key_ptr: *const u8,
    old_master_key_len: c_int,
    new_master_key_ptr: *const u8,
    new_master_key_len: c_int,
    new_label_ptr: *const u8,
    new_label_len: c_int,
    num_reindexing_before_full_set: c_int,
    fetch_all_entry_table_uids: FetchAllEntryTableUidsCallback,
    fetch_entry: FetchEntryTableCallback,
    fetch_chain: FetchChainTableCallback,
    update_lines: UpdateLinesCallback,
    list_removed_locations: ListRemovedLocationsCallback,
) -> c_int {
    let num_reindexing_before_full_set = ffi_unwrap!(
        u32::try_from(num_reindexing_before_full_set)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or_else(|| format!(
                "num_reindexing_before_full_set ({num_reindexing_before_full_set}) should be a \
                 non-zero positive integer."
            )),
        "error converting num_reindexing_before_full_set"
    );

    let old_master_key_bytes =
        ffi_read_bytes!("master key", old_master_key_ptr, old_master_key_len);
    let old_master_key = ffi_unwrap!(
        KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(old_master_key_bytes),
        "error old deserializing master secret key"
    );

    let new_master_key_bytes =
        ffi_read_bytes!("new master key", new_master_key_ptr, new_master_key_len);
    let new_master_key = ffi_unwrap!(
        KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(new_master_key_bytes),
        "error deserializing new master secret key"
    );

    let new_label_bytes = ffi_read_bytes!("new label", new_label_ptr, new_label_len);
    let new_label = Label::from(new_label_bytes);

    let mut findex = FindexUser {
        progress: None,
        fetch_all_entry_table_uids: Some(fetch_all_entry_table_uids),
        fetch_entry: Some(fetch_entry),
        fetch_chain: Some(fetch_chain),
        upsert_entry: None,
        insert_chain: None,
        #[cfg(feature = "compact_live")]
        delete_chain: None,
        update_lines: Some(update_lines),
        list_removed_locations: Some(list_removed_locations),
        #[cfg(feature = "compact_live")]
        filter_removed_locations: None,
    };

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    ffi_unwrap!(
        rt.block_on(findex.compact(
            &old_master_key,
            &new_master_key,
            &new_label,
            num_reindexing_before_full_set.into(),
        )),
        "error waiting for the compact operation to return"
    );

    0
}

#[cfg(feature = "cloud")]
#[no_mangle]
/// Recursively searches Findex graphs for values indexed by the given keywords.
///
/// # Serialization
///
/// Le output is serialized as follows:
///
/// `LEB128(n_keywords) || LEB128(keyword_1)
///     || keyword_1 || LEB128(n_associated_results)
///     || LEB128(associated_result_1) || associated_result_1
///     || ...`
///
/// # Parameters
///
/// - `search_results`          : (output) search result
/// - `token`                   : findex cloud token
/// - `label`                   : public information used to derive UIDs
/// - `keywords`                : `serde` serialized list of base64 keywords
/// - `base_url`                : base URL for Findex Cloud (with http prefix
///   and port if required). If null, use the default Findex Cloud server.
///
/// # Safety
///
/// Cannot be safe since using FFI.
pub unsafe extern "C" fn h_search_cloud(
    search_results_ptr: *mut c_char,
    search_results_len: *mut c_int,
    token_ptr: *const c_char,
    label_ptr: *const u8,
    label_len: c_int,
    keywords_ptr: *const c_char,
    base_url_ptr: *const c_char,
) -> c_int {
    let token = ffi_read_string!("keywords", token_ptr);

    let base_url = if base_url_ptr.is_null() {
        None
    } else {
        Some(ffi_read_string!("base url", base_url_ptr))
    };

    let findex = ffi_unwrap!(
        FindexCloud::new(&token, base_url),
        "error initializing Findex Cloud object"
    );
    let master_key = findex.token.findex_master_key.clone();

    ffi_search(
        findex,
        &master_key,
        search_results_ptr,
        search_results_len,
        label_ptr,
        label_len,
        keywords_ptr,
    )
}

#[cfg(feature = "cloud")]
#[no_mangle]
/// Index the given values for the given keywords. After upserting, any
/// search for such a keyword will result in finding (at least) the
/// corresponding value.
///
/// # Serialization
///
/// The list of values to index for the associated keywords should be serialized
/// as follows:
///
/// `LEB128(n_values) || serialized_value_1
///     || LEB128(n_associated_keywords) || serialized_keyword_1 || ...`
///
/// where values serialized as follows:
///
/// `LEB128(value_bytes.len() + 1) || base64(prefix || value_bytes)`
///
/// with `prefix` being `l` for a `Location` and `w` for a `NextKeyword`, and
/// where keywords are serialized as follows:
///
/// `LEB128(keyword_bytes.len()) || base64(keyword_bytes)`
///
/// # Parameters
///
/// - `token`       : Findex Cloud token
/// - `label`       : additional information used to derive Entry Table UIDs
/// - `additions`   : serialized list of new indexed values
/// - `deletions`   : serialized list of removed indexed values
/// - `base_url`    : base URL for Findex Cloud (with http prefix and port if
///   required). If null, use the default Findex Cloud server.
///
/// # Safety
///
/// Cannot be safe since using FFI.
pub unsafe extern "C" fn h_upsert_cloud(
    token_ptr: *const c_char,
    label_ptr: *const u8,
    label_len: c_int,
    additions_ptr: *const c_char,
    deletions_ptr: *const c_char,
    base_url_ptr: *const c_char,
) -> c_int {
    let token = ffi_read_string!("keywords", token_ptr);

    let base_url = if base_url_ptr.is_null() {
        None
    } else {
        Some(ffi_read_string!("base url", base_url_ptr))
    };

    let findex = ffi_unwrap!(
        FindexCloud::new(&token, base_url),
        "error instantiating Findex Cloud"
    );

    let master_key = findex.token.findex_master_key.clone();

    ffi_upsert(
        findex,
        &master_key,
        label_ptr,
        label_len,
        additions_ptr,
        deletions_ptr,
    )
}

#[cfg(feature = "cloud")]
#[no_mangle]
/// Generate a new Findex token from the provided index ID and signature seeds,
/// and a randomly generated Findex master key inside Rust.
///
/// The token is output inside `token_ptr`, `token_len` is updated to match the
/// token length (this length should always be the same, right now, the length
/// is always below 200 bytes)
///
/// # Safety
///
/// Cannot be safe since using FFI.
pub unsafe extern "C" fn h_generate_new_token(
    token_ptr: *mut u8,
    token_len: *mut c_int,
    index_id_ptr: *const c_char,
    fetch_entries_seed_ptr: *const u8,
    fetch_entries_seed_len: c_int,
    fetch_chains_seed_ptr: *const u8,
    fetch_chains_seed_len: c_int,
    upsert_entries_seed_ptr: *const u8,
    upsert_entries_seed_len: c_int,
    insert_chains_seed_ptr: *const u8,
    insert_chains_seed_len: c_int,
) -> c_int {
    let index_id: String = ffi_read_string!("index id", index_id_ptr);

    let fetch_entries_seed = ffi_read_bytes!(
        "fetch_entries_seed",
        fetch_entries_seed_ptr,
        fetch_entries_seed_len
    );
    let fetch_chains_seed = ffi_read_bytes!(
        "fetch_chains_seed",
        fetch_chains_seed_ptr,
        fetch_chains_seed_len
    );
    let upsert_entries_seed = ffi_read_bytes!(
        "upsert_entries_seed",
        upsert_entries_seed_ptr,
        upsert_entries_seed_len
    );
    let insert_chains_seed = ffi_read_bytes!(
        "insert_chains_seed",
        insert_chains_seed_ptr,
        insert_chains_seed_len
    );

    let token = ffi_unwrap!(
        Token::random_findex_master_key(
            index_id,
            ffi_unwrap!(
                KeyingMaterial::try_from_bytes(fetch_entries_seed),
                "fetch_entries_seed is of wrong size"
            ),
            ffi_unwrap!(
                KeyingMaterial::try_from_bytes(fetch_chains_seed),
                "fetch_chains_seed is of wrong size"
            ),
            ffi_unwrap!(
                KeyingMaterial::try_from_bytes(upsert_entries_seed),
                "upsert_entries_seed is of wrong size"
            ),
            ffi_unwrap!(
                KeyingMaterial::try_from_bytes(insert_chains_seed),
                "insert_chains_seed is of wrong size"
            ),
        ),
        "cannot generate random findex master key"
    );

    ffi_write_bytes!(
        "search results",
        token.to_string().as_bytes(),
        token_ptr,
        token_len
    );

    0
}

/// Helper to merge the cloud and non-cloud implementations
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[allow(clippy::too_many_arguments)]
unsafe fn ffi_search<
    Error: std::error::Error + CallbackError + ToErrorCode,
    T: FindexSearch<
            UID_LENGTH,
            BLOCK_LENGTH,
            CHAIN_TABLE_WIDTH,
            MASTER_KEY_LENGTH,
            KWI_LENGTH,
            KMAC_KEY_LENGTH,
            DEM_KEY_LENGTH,
            KmacKey,
            DemScheme,
            Error,
        >,
>(
    mut findex: T,
    master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
    search_results_ptr: *mut c_char,
    search_results_len: *mut c_int,
    label_ptr: *const u8,
    label_len: c_int,
    keywords_ptr: *const c_char,
) -> c_int {
    let label_bytes = ffi_read_bytes!("label", label_ptr, label_len);
    let label = Label::from(label_bytes);

    // Why keywords are JSON array of base64 strings? We should change this to send
    // raw bytes with leb128 prefix or something like that.
    // <https://github.com/Cosmian/findex/issues/19>

    let keywords_as_json_string = ffi_read_string!("keywords", keywords_ptr);
    let keywords_as_base64_vec: Vec<String> = ffi_unwrap!(
        serde_json::from_str(&keywords_as_json_string),
        "failed deserializing the keywords from JSON"
    );
    let mut keywords = HashSet::with_capacity(keywords_as_base64_vec.len());
    for keyword_as_base64 in keywords_as_base64_vec {
        // base64 decode the words
        let word_bytes = ffi_unwrap!(
            STANDARD.decode(keyword_as_base64),
            "error decoding base64 keyword"
        );
        keywords.insert(Keyword::from(word_bytes));
    }

    // We want to forward error code returned by callbacks to the parent caller to
    // do error management client side.
    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    let results = match rt.block_on(findex.search(master_key, &label, keywords)) {
        Ok(results) => results,
        Err(FindexError::Callback(e)) => {
            set_last_error(FfiError::Generic(e.to_string()));
            return e.to_error_code();
        }
        Err(e) => {
            set_last_error(FfiError::Generic(e.to_string()));
            return 1;
        }
    };

    // Serialize the results.
    // We should be able to use the output buffer as the Serializer sink to avoid to
    // copy the buffer (right now the crypto_core serializer doesn't provide à
    // constructor from an existing slice)
    // <https://github.com/Cosmian/findex/issues/20>
    let mut serializer = Serializer::new();
    ffi_unwrap!(
        serializer.write_leb128_u64(results.len() as u64),
        "error serializing length"
    );
    for (keyword, locations) in results {
        ffi_unwrap!(serializer.write_vec(&keyword), "error serializing keyword");
        ffi_unwrap!(
            serializer.write_array(&ffi_unwrap!(
                serialize_set(&locations),
                "error serializing set"
            )),
            "error serializing locations"
        );
    }
    let serialized_uids = serializer.finalize();

    ffi_write_bytes!(
        "search results",
        &serialized_uids,
        search_results_ptr,
        search_results_len
    );

    0
}

/// Helper to merge the cloud and non-cloud implementations
///
/// # Safety
///
/// Cannot be safe since using FFI.
unsafe extern "C" fn ffi_upsert<
    Error: std::error::Error + CallbackError + ToErrorCode,
    T: FindexUpsert<
            UID_LENGTH,
            BLOCK_LENGTH,
            CHAIN_TABLE_WIDTH,
            MASTER_KEY_LENGTH,
            KWI_LENGTH,
            KMAC_KEY_LENGTH,
            DEM_KEY_LENGTH,
            KmacKey,
            DemScheme,
            Error,
        >,
>(
    mut findex: T,
    master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
    label_ptr: *const u8,
    label_len: c_int,
    additions_ptr: *const c_char,
    deletions_ptr: *const c_char,
) -> c_int {
    let label_bytes = ffi_read_bytes!("label", label_ptr, label_len);
    let label = Label::from(label_bytes);

    let additions = ffi_unwrap!(
        parse_indexed_values(&ffi_read_string!(
            "added indexed values and keywords",
            additions_ptr
        ),),
        "failed parsing added indexed values"
    );

    let deletions = ffi_unwrap!(
        parse_indexed_values(&ffi_read_string!(
            "deleted indexed values and keywords",
            deletions_ptr
        ),),
        "failed parsing deleted indexed values"
    );

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    // We want to forward error code returned by callbacks to the parent caller to
    // do error management client side.
    match rt.block_on(findex.upsert(master_key, &label, additions, deletions)) {
        Ok(_) => 0,
        Err(FindexError::Callback(e)) => {
            set_last_error(FfiError::Generic(e.to_string()));
            e.to_error_code()
        }
        Err(e) => {
            set_last_error(FfiError::Generic(e.to_string()));
            1
        }
    }
}
