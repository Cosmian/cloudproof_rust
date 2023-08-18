//! Defines the Findex FFI API.

use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::{bytes_ser_de::Serializer, FixedSizeCBytes, SymmetricKey};
use cosmian_ffi_utils::{
    error::{h_get_error, set_last_error, FfiError},
    ffi_bail, ffi_read_bytes, ffi_unwrap, ffi_write_bytes,
};
use cosmian_findex::{
    Error as FindexError, IndexedValue, IndexedValueToKeywordsMap, Keyword, Keywords, Label,
    Location, USER_KEY_LENGTH,
};
use tracing::trace;

#[cfg(debug_assertions)]
use crate::logger::log_init;
use crate::{
    backends::custom::ffi::{Delete, DumpTokens, Fetch, FfiCallbacks, Insert, Upsert},
    ser_de::ffi_ser_de::{
        deserialize_indexed_values, deserialize_keyword_set, serialize_keyword_set,
        serialize_location_set,
    },
    BackendConfiguration, InstantiatedFindex,
};

/// Re-export the `cosmian_ffi` `h_get_error` function to clients with the old
/// `get_last_error` name The `h_get_error` is available inside the final lib
/// (but tools like `ffigen` seems to not parse it…) Maybe we can find a
/// solution by changing the function name inside the clients.
///
/// # Safety
///
/// It's unsafe.
#[no_mangle]
pub unsafe extern "C" fn get_last_error(error_ptr: *mut i8, error_len: *mut i32) -> i32 {
    h_get_error(error_ptr, error_len)
}

pub async fn no_interrupt(
    _: HashMap<Keyword, HashSet<IndexedValue<Keyword, Location>>>,
) -> Result<bool, String>
where
    HashMap<Keyword, HashSet<IndexedValue<Keyword, Location>>>: std::fmt::Debug,
    Result<bool, String>: std::fmt::Debug,
{
    Ok(false)
}

pub async fn no_filter_obsolete_data(
    locations: HashSet<Location>,
) -> Result<HashSet<Location>, String>
where
    HashSet<Location>: std::fmt::Debug,
    Result<HashSet<Location>, String>: std::fmt::Debug,
{
    Ok(locations)
}

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
/// - `key`                     : Findex key
/// - `label`                   : public information used to derive UIDs
/// - `keywords`                : serialized list of keywords
/// - `entry_table_number`      : number of different entry tables
/// - `progress_callback`       : callback used to retrieve intermediate results
///   and transmit user interrupt
/// - `fetch_entry_callback`    : callback used to fetch the Entry Table
/// - `fetch_chain_callback`    : callback used to fetch the Chain Table
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_search(
    search_results_ptr: *mut u8,
    search_results_len: *mut i32,
    key_ptr: *const u8,
    key_len: u32,
    label_ptr: *const u8,
    label_len: u32,
    keywords_ptr: *const u8,
    keywords_len: u32,
    entry_table_number: u32,
    fetch_entry_callback: Fetch,
    fetch_chain_callback: Fetch,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init();

    let key_bytes = ffi_read_bytes!("key", key_ptr, key_len);
    let key = ffi_unwrap!(
        SymmetricKey::try_from_slice(key_bytes),
        "error deserializing findex key"
    );
    trace!("Key successfully parsed");

    let label_bytes = ffi_read_bytes!("label", label_ptr, label_len);
    let label = Label::from(label_bytes);
    trace!("Label successfully parsed: label: {label}");

    let keywords = ffi_unwrap!(
        deserialize_keyword_set(ffi_read_bytes!("keywords", keywords_ptr, keywords_len)),
        "error deserializing keywords"
    );
    let keywords = Keywords::from(keywords);
    trace!("Keywords successfully parsed: keywords: {keywords}");

    if entry_table_number == 0 {
        ffi_bail!("The parameter entry_table_number must be strictly positive. Found 0");
    }
    trace!("Entry table number: {entry_table_number}");

    let _user_interrupt =
        |_res: HashMap<Keyword, HashSet<IndexedValue<Keyword, Location>>>| async { false }; //TODO

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    let config = BackendConfiguration::Ffi(
        FfiCallbacks {
            table_number: entry_table_number as usize,
            fetch: Some(fetch_entry_callback),
            upsert: None,
            insert: None,
            delete: None,
            dump_tokens: None,
        },
        FfiCallbacks {
            table_number: 1,
            fetch: Some(fetch_chain_callback),
            upsert: None,
            insert: None,
            delete: None,
            dump_tokens: None,
        },
    );

    let findex = ffi_unwrap!(
        rt.block_on(InstantiatedFindex::new(config)),
        "error instantiating Findex"
    );

    let results = match rt.block_on(findex.search(&key, &label, keywords, &no_interrupt)) {
        Ok(results) => results,
        Err(FindexError::Callback(e)) => {
            set_last_error(FfiError::Generic(e.to_string()));
            // return e.to_error_code(); TODO
            return 1;
        }
        Err(e) => {
            set_last_error(FfiError::Generic(e.to_string()));
            return 1;
        }
    };

    // Serialize the results.
    // We should be able to use the output buffer as the `Serializer` sink to avoid
    // to copy the buffer (right now the `crypto_core` serializer doesn't provide a
    // constructor from an existing slice) <https://github.com/Cosmian/findex/issues/20>
    let mut serializer = Serializer::new();
    ffi_unwrap!(
        serializer.write_leb128_u64(results.len() as u64),
        "error serializing length"
    );
    for (keyword, locations) in results {
        ffi_unwrap!(serializer.write_vec(&keyword), "error serializing keyword");
        let serialized_location_set =
            ffi_unwrap!(serialize_location_set(&locations), "error serializing set");
        ffi_unwrap!(
            serializer.write_array(&serialized_location_set),
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
/// The results are serialized as follows:
///
/// `LEB128(n_values) || serialized_value_1 || ... || serialized_value_n`
///
/// and `serialized_value_i` is serialized as follows:
/// `LEB128(keyword_bytes.len()) || keyword_bytes`
///
/// # Parameters
///
/// - `upsert_results`  : Returns the list of new keywords added to the index
/// - `key`      : Findex key
/// - `label`           : additional information used to derive Entry Table UIDs
/// TODO (TBZ): explain the serialization in the doc
/// - `additions`       : serialized list of new indexed values
/// - `deletions`       : serialized list of removed indexed values
/// - `entry_table_number` : number of different entry tables
/// - `fetch_entry`     : callback used to fetch the Entry Table
/// - `upsert_entry`    : callback used to upsert lines in the Entry Table
/// - `insert_chain`    : callback used to insert lines in the Chain Table
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_upsert(
    upsert_results_ptr: *mut i8,
    upsert_results_len: *mut i32,
    key_ptr: *const u8,
    key_len: i32,
    label_ptr: *const u8,
    label_len: i32,
    additions_ptr: *const i8,
    additions_len: i32,
    deletions_ptr: *const i8,
    deletions_len: i32,
    entry_table_number: u32,
    fetch_entry: Fetch, // TODO: create init function to pass callbacks
    upsert_entry: Upsert,
    insert_chain: Insert,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init();

    let key_bytes = ffi_read_bytes!("key", key_ptr, key_len);
    let key = ffi_unwrap!(
        SymmetricKey::try_from_slice(key_bytes),
        "error re-serializing findex key"
    );
    if entry_table_number == 0 {
        ffi_bail!("The parameter entry_table_number must be strictly positive. Found 0");
    }

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    let config = BackendConfiguration::Ffi(
        FfiCallbacks {
            table_number: entry_table_number as usize,
            fetch: Some(fetch_entry),
            upsert: Some(upsert_entry),
            insert: None,
            delete: None,
            dump_tokens: None,
        },
        FfiCallbacks {
            table_number: 1,
            fetch: None,
            upsert: None,
            insert: Some(insert_chain),
            delete: None,
            dump_tokens: None,
        },
    );

    let mut findex = ffi_unwrap!(
        rt.block_on(InstantiatedFindex::new(config)),
        "error instantiating Findex"
    );

    ffi_upsert(
        &mut findex,
        &key,
        upsert_results_ptr,
        upsert_results_len,
        label_ptr,
        label_len,
        additions_ptr,
        additions_len,
        deletions_ptr,
        deletions_len,
    )
}

/// Replaces all the Index Entry Table UIDs and values. New UIDs are derived
/// using the given label and the KMAC key derived from the new key. The
/// values are decrypted using the DEM key derived from the key and
/// re-encrypted using the DEM key derived from the new key.
///
/// Randomly selects index entries and recompact their associated chains. Chains
/// indexing no existing location are removed. Others are recomputed from a new
/// keying material. This removes unneeded paddings. New UIDs are derived for
/// the chain and values are re-encrypted using a DEM key derived from the new
/// keying material.
///
/// # Parameters
///
/// - `old_key`                         : old Findex key
/// - `new_key`                         : new Findex key
/// - `new_label`                       : public information used to derive UIDs
/// - `num_reindexing_before_full_set`  : number of compact operation needed to
///   compact all the Chain Table
/// - `entry_table_number`               : number of different entry tables
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
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_compact(
    // TODO: add FFI tests on h_search, h_upsert, h_compact
    old_key_ptr: *const u8,
    old_key_len: i32,
    new_key_ptr: *const u8,
    new_key_len: i32,
    old_label_ptr: *const u8,
    old_label_len: i32,
    new_label_ptr: *const u8,
    new_label_len: i32,
    n_compact_to_full: u32,
    entry_table_number: u32,
    fetch_entry: Fetch,
    fetch_chain: Fetch,
    upsert_entry: Upsert,
    insert_chain: Insert,
    delete_entry: Delete,
    delete_chain: Delete,
    dump_tokens_entry: DumpTokens,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init(); //TODO: memo: warning, findex-cloud is broken with this refactor

    if n_compact_to_full == 0 {
        ffi_bail!("The parameter n_compact_to_full must be strictly positive. Found 0");
    }

    if entry_table_number == 0 {
        ffi_bail!("The parameter entry_table_number must be strictly positive. Found 0");
    }

    let old_key_bytes = ffi_read_bytes!("key", old_key_ptr, old_key_len);
    let old_key = ffi_unwrap!(
        SymmetricKey::try_from_slice(old_key_bytes),
        "error deserializing old findex key"
    );

    let new_key_bytes = ffi_read_bytes!("new key", new_key_ptr, new_key_len);
    let new_key = ffi_unwrap!(
        SymmetricKey::try_from_slice(new_key_bytes),
        "error deserializing new findex key"
    );

    let old_label_bytes = ffi_read_bytes!("old label", old_label_ptr, old_label_len);
    let old_label = Label::from(old_label_bytes);

    let new_label_bytes = ffi_read_bytes!("new label", new_label_ptr, new_label_len);
    let new_label = Label::from(new_label_bytes);

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    let config = BackendConfiguration::Ffi(
        FfiCallbacks {
            table_number: entry_table_number as usize,
            fetch: Some(fetch_entry),
            upsert: Some(upsert_entry),
            insert: None,
            delete: Some(delete_entry),
            dump_tokens: Some(dump_tokens_entry),
        },
        FfiCallbacks {
            table_number: 1,
            fetch: Some(fetch_chain),
            upsert: None,
            insert: Some(insert_chain),
            delete: Some(delete_chain),
            dump_tokens: None,
        },
    );

    let findex = ffi_unwrap!(
        rt.block_on(InstantiatedFindex::new(config)),
        "error instantiating Findex"
    );

    ffi_unwrap!(
        rt.block_on(findex.compact(
            &old_key,
            &new_key,
            &old_label,
            &new_label,
            n_compact_to_full as usize,
            &no_filter_obsolete_data
        )),
        "error waiting for the compact operation to return"
    );

    0
}

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
/// - `token`                   : Findex cloud token
/// - `label`                   : public information used to derive UIDs
/// - `keywords`                : `serde` serialized list of base64 keywords
/// - `base_url`                : base URL for Findex Cloud (with http prefix
///   and port if required). If null, use the default Findex Cloud server.
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[cfg(feature = "cloud")]
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_search_cloud(
    search_results_ptr: *mut i8,
    search_results_len: *mut i32,
    token_ptr: *const i8,
    label_ptr: *const u8,
    label_len: i32,
    keywords_ptr: *const u8,
    keywords_len: u32,
    base_url_ptr: *const i8,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init();

    let token = ffi_read_string!("token", token_ptr);
    let authorization_token = ffi_unwrap!(
        crate::backends::cloud::Token::from_str(&token),
        "conversion failed of findex cloud authorization token"
    );

    let label_bytes = ffi_read_bytes!("label", label_ptr, label_len);
    let label = Label::from(label_bytes);
    trace!("Label successfully parsed: label: {label}");

    let keywords = ffi_unwrap!(
        deserialize_keywords_set(ffi_read_bytes!("keywords", keywords_ptr, keywords_len)),
        "error deserializing keywords"
    );
    let keywords = Keywords::from(keywords);
    trace!("Keywords successfully parsed: keywords: {keywords}");

    let base_url = if base_url_ptr.is_null() {
        None
    } else {
        Some(ffi_read_string!("base url", base_url_ptr))
    };

    let config = BackendConfiguration::Cloud(
        ffi_unwrap!(
            CloudParameters::from(&token, base_url.clone()),
            "create cloud parameters failed (entry)"
        ),
        ffi_unwrap!(
            CloudParameters::from(&token, base_url.clone()),
            "create cloud parameters failed (chain)"
        ),
    );

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    let findex = ffi_unwrap!(
        rt.block_on(InstantiatedFindex::new(config)),
        "error instantiating Findex"
    );

    trace!("instantiated Findex: {findex:?}");

    // let key = findex.token.findex_key.clone();

    let results = match rt.block_on(findex.search(
        &authorization_token.findex_key,
        &label,
        keywords,
        &no_interrupt,
    )) {
        Ok(results) => results,
        Err(FindexError::Callback(e)) => {
            set_last_error(FfiError::Generic(e.to_string()));
            // return e.to_error_code(); TODO
            return 1;
        }
        Err(e) => {
            set_last_error(FfiError::Generic(e.to_string()));
            return 1;
        }
    };

    // Serialize the results.
    // We should be able to use the output buffer as the `Serializer` sink to avoid
    // to copy the buffer (right now the `crypto_core` serializer doesn't provide a
    // constructor from an existing slice) <https://github.com/Cosmian/findex/issues/20>
    let mut serializer = Serializer::new();
    ffi_unwrap!(
        serializer.write_leb128_u64(results.len() as u64),
        "error serializing length"
    );
    for (keyword, locations) in results {
        ffi_unwrap!(serializer.write_vec(&keyword), "error serializing keyword");
        let serialized_location_set =
            ffi_unwrap!(serialize_location_set(&locations), "error serializing set");
        ffi_unwrap!(
            serializer.write_array(&serialized_location_set),
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
/// The results are serialized as follows:
///
/// `LEB128(n_values) || serialized_value_1 || ... || serialized_value_n`
///
/// and `serialized_value_i` is serialized as follows:
/// `LEB128(keyword_bytes.len()) || keyword_bytes`
///
/// # Parameters
///
/// - `upsert_results` : Returns the list of new keywords added to the index
/// - `token`          : Findex Cloud token
/// - `label`          : additional information used to derive Entry Table UIDs
/// - `additions`      : serialized list of new indexed values
/// - `deletions`      : serialized list of removed indexed values
/// - `base_url`       : base URL for Findex Cloud (with http prefix and port if
///   required). If null, use the default Findex Cloud server.
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[cfg(feature = "cloud")]
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_upsert_cloud(
    upsert_results_ptr: *mut i8,
    upsert_results_len: *mut i32,
    token_ptr: *const i8,
    label_ptr: *const u8,
    label_len: i32,
    additions_ptr: *const i8,
    additions_len: i32,
    deletions_ptr: *const i8,
    deletions_len: i32,
    base_url_ptr: *const i8,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init();

    let token = ffi_read_string!("token", token_ptr);
    trace!("Authorization token read: {token}");
    let authorization_token = ffi_unwrap!(
        crate::backends::cloud::Token::from_str(&token),
        "conversion failed of findex cloud authorization token"
    );

    let base_url = if base_url_ptr.is_null() {
        None
    } else {
        Some(ffi_read_string!("base url", base_url_ptr))
    };

    let config = BackendConfiguration::Cloud(
        ffi_unwrap!(
            CloudParameters::from(&token, base_url.clone()),
            "create cloud parameters failed (entry)"
        ),
        ffi_unwrap!(
            CloudParameters::from(&token, base_url.clone()),
            "create cloud parameters failed (chain)"
        ),
    );

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    let mut findex = ffi_unwrap!(
        rt.block_on(InstantiatedFindex::new(config)),
        "error instantiating Findex"
    );
    trace!("instantiated Findex: {findex:?}");

    ffi_upsert(
        &mut findex,
        &authorization_token.findex_key,
        upsert_results_ptr,
        upsert_results_len,
        label_ptr,
        label_len,
        additions_ptr,
        additions_len,
        deletions_ptr,
        deletions_len,
    )
}

/// Generate a new Findex token from the provided index ID and signature seeds,
/// and a randomly generated Findex key inside Rust.
///
/// The token is output inside `token_ptr`, `token_len` is updated to match the
/// token length (this length should always be the same, right now, the length
/// is always below 200 bytes)
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[cfg(feature = "cloud")]
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_generate_new_token(
    _token_ptr: *mut u8,
    _token_len: *mut i32,
    _index_id_ptr: *const i8,
    // index_id: u32,
    _fetch_entries_seed_ptr: *const u8,
    _fetch_entries_seed_len: i32,
    _fetch_chains_seed_ptr: *const u8,
    _fetch_chains_seed_len: i32,
    _upsert_entries_seed_ptr: *const u8,
    _upsert_entries_seed_len: i32,
    _insert_chains_seed_ptr: *const u8,
    _insert_chains_seed_len: i32,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init();

    // let index_id: String = ffi_read_string!("index id", index_id_ptr);

    // let fetch_entries_seed = ffi_read_bytes!(
    //     "fetch_entries_seed",
    //     fetch_entries_seed_ptr,
    //     fetch_entries_seed_len
    // );
    // let fetch_chains_seed = ffi_read_bytes!(
    //     "fetch_chains_seed",
    //     fetch_chains_seed_ptr,
    //     fetch_chains_seed_len
    // );
    // let upsert_entries_seed = ffi_read_bytes!(
    //     "upsert_entries_seed",
    //     upsert_entries_seed_ptr,
    //     upsert_entries_seed_len
    // );
    // let insert_chains_seed = ffi_read_bytes!(
    //     "insert_chains_seed",
    //     insert_chains_seed_ptr,
    //     insert_chains_seed_len
    // );

    // let mut seeds = HashMap::new();
    // seeds.insert(
    //     CallbackPrefix::Fetch,
    //     ffi_unwrap!(
    //         SymmetricKey::try_from_slice(fetch_entries_seed),
    //         "fetch_entries_seed is of wrong size"
    //     ),
    // );
    // seeds.insert(
    //     CallbackPrefix::Fetch,
    //     ffi_unwrap!(
    //         SymmetricKey::try_from_slice(fetch_chains_seed),
    //         "fetch_chains_seed is of wrong size"
    //     ),
    // );
    // seeds.insert(
    //     CallbackPrefix::Upsert,
    //     ffi_unwrap!(
    //         SymmetricKey::try_from_slice(upsert_entries_seed),
    //         "upsert_entries_seed is of wrong size"
    //     ),
    // );
    // seeds.insert(
    //     CallbackPrefix::Insert,
    //     ffi_unwrap!(
    //         SymmetricKey::try_from_slice(insert_chains_seed),
    //         "insert_chains_seed is of wrong size"
    //     ),
    // );

    // let token = AuthorizationToken::new(index_id, seeds);

    // ffi_write_bytes!(
    //     "search results",
    //     token.to_string().as_bytes(),
    //     token_ptr,
    //     token_len
    // );

    0
}

fn get_upsert_output_size(
    additions: &HashMap<IndexedValue<Keyword, Location>, Keywords>,
    deletions: &HashMap<IndexedValue<Keyword, Location>, Keywords>,
) -> usize {
    // Since `h_upsert` returns the set of keywords that have been inserted (and
    // deleted), caller MUST know in advance how much memory is needed before
    // calling `h_upsert`. In order to centralize into Rust the computation of the
    // allocation size, 2 calls to `h_upsert` are required:
    // - the first call is made with `upsert_results_len` with a 0 value. No
    //   indexation at all is done. It simply returns an upper bound estimation of
    //   the allocation size considering the maps `additions` and `deletions`.
    // - the second call takes this returned value for `upsert_results_len`
    additions
        .values()
        .flat_map(|set| set.iter().map(|e| e.len() + 8))
        .sum::<usize>()
        + deletions
            .values()
            .flat_map(|set| set.iter().map(|e| e.len() + 8))
            .sum::<usize>()
}
/// Helper to merge the cloud and non-cloud implementations
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[tracing::instrument(ret, skip_all)]
unsafe extern "C" fn ffi_upsert(
    // TODO: remove this function?
    findex: &mut InstantiatedFindex,
    key: &SymmetricKey<USER_KEY_LENGTH>,
    upsert_results_ptr: *mut i8,
    upsert_results_len: *mut i32,
    label_ptr: *const u8,
    label_len: i32,
    additions_ptr: *const i8,
    additions_len: i32,
    deletions_ptr: *const i8,
    deletions_len: i32,
) -> i32 {
    let label_bytes = ffi_read_bytes!("label", label_ptr, label_len);
    let label = Label::from(label_bytes);

    let additions_bytes = ffi_read_bytes!("additions", additions_ptr, additions_len);
    let additions = IndexedValueToKeywordsMap::from(ffi_unwrap!(
        deserialize_indexed_values(additions_bytes),
        "failed deserialize indexed values (additions)"
    ));

    let deletions_bytes = ffi_read_bytes!("deletions", deletions_ptr, deletions_len);
    let deletions = IndexedValueToKeywordsMap::from(ffi_unwrap!(
        deserialize_indexed_values(deletions_bytes),
        "failed deserialize indexed values (deletions)"
    ));

    let output_size = get_upsert_output_size(&additions, &deletions);
    if *upsert_results_len < output_size as i32 {
        set_last_error(FfiError::Generic(format!(
            "The pre-allocated upsert_result buffer is too small; need {} bytes, allocated {}",
            output_size, upsert_results_len as i32
        )));
        *upsert_results_len = output_size as i32;
        return 1;
    }

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    // We want to forward error code returned by callbacks to the parent caller to
    // do error management client side.
    let new_keywords = match rt.block_on(findex.add(key, &label, additions)) {
        Ok(new_keywords) => new_keywords,
        Err(FindexError::Callback(e)) => {
            set_last_error(FfiError::Generic(e.to_string()));
            // return e.to_error_code();TODO
            return 1;
        }
        Err(e) => {
            set_last_error(FfiError::Generic(e.to_string()));
            return 1;
        }
    };

    // Serialize the results.
    let serialized_keywords = ffi_unwrap!(
        serialize_keyword_set(&new_keywords),
        "serialize new keywords"
    );

    // Deletions
    let _deleted_keywords = match rt.block_on(findex.delete(key, &label, deletions)) {
        Ok(deleted_keywords) => deleted_keywords,
        Err(FindexError::Callback(e)) => {
            set_last_error(FfiError::Generic(e.to_string()));
            // return e.to_error_code();TODO
            return 1;
        }
        Err(e) => {
            set_last_error(FfiError::Generic(e.to_string()));
            return 1;
        }
    };

    ffi_write_bytes!(
        "upsert results",
        &serialized_keywords,
        upsert_results_ptr,
        upsert_results_len
    );

    0
}
