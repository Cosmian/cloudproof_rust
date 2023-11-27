//! Defines the Findex FFI API.

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Mutex,
};

use cosmian_crypto_core::{
    bytes_ser_de::Serializer, reexport::rand_core::SeedableRng, CsRng, FixedSizeCBytes,
    RandomFixedSizeCBytes, SymmetricKey,
};
use cosmian_ffi_utils::{
    error::{h_get_error, set_last_error, FfiError},
    ffi_read_bytes, ffi_read_string, ffi_unwrap, ffi_write_bytes, ErrorCode,
};
use cosmian_findex::{
    Error as FindexError, IndexedValue, IndexedValueToKeywordsMap, Keyword, Keywords, Label,
    Location, USER_KEY_LENGTH,
};
use lazy_static::lazy_static;
use tracing::trace;

#[cfg(debug_assertions)]
use crate::logger::log_init;
use crate::{
    backends::{
        custom::ffi::{
            Delete, DumpTokens, Fetch, FfiCallbacks, FilterObsoleteData, Insert, Interrupt, Upsert,
        },
        rest::{AuthorizationToken, CallbackPrefix},
        BackendError,
    },
    ser_de::ffi_ser_de::{
        deserialize_indexed_values, deserialize_keyword_set, deserialize_location_set,
        get_upsert_output_size, serialize_intermediate_results, serialize_keyword_set,
        serialize_location_set,
    },
    BackendConfiguration, InstantiatedFindex,
};

lazy_static! {
    static ref FINDEX_INSTANCES: Mutex::<HashMap::<i32, (SymmetricKey<USER_KEY_LENGTH>, Label, InstantiatedFindex)>> =
        Mutex::new(HashMap::new());
}

/// Creates a new Findex instance using a custom FFI backend.
///
/// The new instance is stored in a cache and the handle returned.
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_instantiate_with_ffi_backend(
    findex_handle: *mut i32,
    key_ptr: *const u8,
    key_len: i32,
    label_ptr: *const u8,
    label_len: i32,
    entry_table_number: u32,
    fetch_entry: Fetch,
    fetch_chain: Fetch,
    upsert_entry: Upsert,
    insert_chain: Insert,
    delete_entry: Delete,
    delete_chain: Delete,
    dump_tokens: DumpTokens,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init();

    let key_bytes = ffi_read_bytes!("key", key_ptr, key_len);
    let key = ffi_unwrap!(
        SymmetricKey::try_from_slice(key_bytes),
        "error deserializing findex key",
        ErrorCode::Serialization.into()
    );
    trace!("Key successfully parsed");

    let label_bytes = ffi_read_bytes!("label", label_ptr, label_len);
    let label = Label::from(label_bytes);
    trace!("Label successfully parsed: label: {label}");

    let config = BackendConfiguration::Ffi(
        FfiCallbacks {
            table_number: entry_table_number as usize,
            fetch: Some(fetch_entry),
            upsert: Some(upsert_entry),
            insert: None,
            delete: Some(delete_entry),
            dump_tokens: Some(dump_tokens),
        },
        FfiCallbacks {
            // Only one Chain table is allowed.
            table_number: 1,
            fetch: Some(fetch_chain),
            upsert: None,
            insert: Some(insert_chain),
            delete: Some(delete_chain),
            dump_tokens: None,
        },
    );

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );
    let findex = ffi_unwrap!(
        rt.block_on(InstantiatedFindex::new(config)),
        "error instantiating Findex with custom backend",
        ErrorCode::Findex.into()
    );

    let mut cache = FINDEX_INSTANCES
        .lock()
        .expect("Findex instance cache lock poisoned.");
    let handle = ffi_unwrap!(
        <i32>::try_from(cache.len()),
        "findex instance cache capacity overflow",
        ErrorCode::Findex.into()
    );

    cache.insert(handle, (key, label, findex));

    *findex_handle = handle;

    ErrorCode::Success.into()
}

/// Instantiate a Findex using a REST backend.
///
/// # Parameters
///
/// - `label`   : label used by Findex
/// - `token`   : token containing authentication keys
/// - `url`     : REST server URL
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_instantiate_with_rest_backend(
    findex_handle: *mut i32,
    label_ptr: *const u8,
    label_len: i32,
    token_ptr: *const i8,
    url_ptr: *const i8,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init();

    let label_bytes = ffi_read_bytes!("label", label_ptr, label_len);
    let label = Label::from(label_bytes);
    trace!("Label successfully parsed: label: {label}");

    let token = ffi_read_string!("token", token_ptr);
    trace!("Authorization token read: {token}");
    let authorization_token = ffi_unwrap!(
        crate::backends::rest::AuthorizationToken::from_str(&token),
        "authorization token conversion failed",
        ErrorCode::Backend.into()
    );

    let base_url = if url_ptr.is_null() {
        String::new()
    } else {
        ffi_read_string!("REST server URL", url_ptr)
    };

    let config = BackendConfiguration::Rest(authorization_token.clone(), base_url);

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );
    let findex = ffi_unwrap!(
        rt.block_on(InstantiatedFindex::new(config)),
        "error instantiating Findex with REST backend",
        ErrorCode::Backend.into()
    );

    let mut cache = FINDEX_INSTANCES
        .lock()
        .expect("Findex instance cache lock poisoned.");
    let handle = ffi_unwrap!(
        <i32>::try_from(cache.len()),
        "findex instance cache capacity overflow",
        ErrorCode::Findex.into()
    );
    cache.insert(handle, (authorization_token.findex_key, label, findex));

    *findex_handle = handle;

    ErrorCode::Success.into()
}

/// Instantiate a Findex using a Redis backend.
///
/// # Parameters
///
/// - `key`     : findex key
/// - `label`   : label used by Findex
/// - `entry_table_redis_url`     : Redis entry table URL
/// - `chain_table_redis_url`     : Redis chain table URL
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_instantiate_with_redis_backend(
    findex_handle: *mut i32,
    key_ptr: *const u8,
    key_len: i32,
    label_ptr: *const u8,
    label_len: i32,
    entry_table_redis_url_ptr: *const i8,
    chain_table_redis_url_ptr: *const i8,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init();

    let key_bytes = ffi_read_bytes!("key", key_ptr, key_len);
    let key = ffi_unwrap!(
        SymmetricKey::try_from_slice(key_bytes),
        "error deserializing findex key",
        ErrorCode::Serialization.into()
    );
    trace!("Key successfully parsed");

    let label_bytes = ffi_read_bytes!("label", label_ptr, label_len);
    let label = Label::from(label_bytes);
    trace!("Label successfully parsed: label: {label}");

    let entry_table_redis_url =
        ffi_read_string!("Redis entry table URL", entry_table_redis_url_ptr);
    let chain_table_redis_url =
        ffi_read_string!("Redis chain table URL", chain_table_redis_url_ptr);

    let config = BackendConfiguration::Redis(entry_table_redis_url, chain_table_redis_url);

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );
    let findex = ffi_unwrap!(
        rt.block_on(InstantiatedFindex::new(config)),
        "error instantiating Findex with REST backend",
        ErrorCode::Findex.into()
    );

    let mut cache = FINDEX_INSTANCES
        .lock()
        .expect("Findex instance cache lock poisoned.");
    let handle = ffi_unwrap!(
        <i32>::try_from(cache.len()),
        "findex instance cache capacity overflow",
        ErrorCode::Findex.into()
    );
    cache.insert(handle, (key, label, findex));

    *findex_handle = handle;

    ErrorCode::Success.into()
}

/// Searches the index for the given keywords.
///
/// At each search recursion, the passed `interrupt` function is called with the
/// results from the current recursion level. The search is interrupted is
/// `true` is returned.
///
/// # Parameters
///
/// - `results`         : (output) search result
/// - `findex_handle`   : Findex handle on the instance cache
/// - `keywords`        : serialized list of keywords
/// - `interrupt`       : user interrupt called at each search iteration
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_search(
    results_ptr: *mut u8,
    results_len: *mut i32,
    findex_handle: i32,
    keywords_ptr: *const u8,
    keywords_len: i32,
    interrupt: Interrupt,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init();

    let keywords = ffi_unwrap!(
        deserialize_keyword_set(ffi_read_bytes!("keywords", keywords_ptr, keywords_len)),
        "error deserializing keywords",
        ErrorCode::Serialization.into()
    );
    let keywords = Keywords::from(keywords);
    trace!("Keywords successfully parsed: keywords: {keywords}");

    let user_interrupt = |res: HashMap<Keyword, HashSet<IndexedValue<Keyword, Location>>>| async move {
        trace!("user interrupt input: {res:?}");
        let bytes = serialize_intermediate_results(&res).map_err(|e| e.to_string())?;
        let length = <u32>::try_from(bytes.len()).map_err(|e| e.to_string())?;
        let is_interrupted = 1 == (interrupt)(bytes.as_ptr(), length);
        trace!("user interrupt output: = {is_interrupted}");
        Ok(is_interrupted)
    };

    let cache = FINDEX_INSTANCES
        .lock()
        .expect("Findex instance cache lock poisoned.");
    let (key, label, findex) = ffi_unwrap!(
        cache
            .get(&findex_handle)
            .ok_or_else(|| format!("no matching instance for handle {findex_handle}")),
        "cannot get a hold on the Findex instance",
        ErrorCode::Findex.into()
    );

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    let res = rt.block_on(findex.search(key, label, keywords, &user_interrupt));

    let results = match res {
        Ok(res) => res,
        Err(FindexError::Callback(BackendError::Ffi(msg, code))) => {
            set_last_error(FfiError::Generic(format!(
                "backend error during `search` operation: {msg}"
            )));
            return code.into();
        }
        Err(e) => {
            set_last_error(FfiError::Generic(format!("findex `search` error: {e}")));
            return ErrorCode::Findex.into();
        }
    };

    // Serialize the results.
    // We should be able to use the output buffer as the `Serializer` sink to avoid
    // to copy the buffer (right now the `crypto_core` serializer doesn't provide a
    // constructor from an existing slice) <https://github.com/Cosmian/findex/issues/20>
    let mut serializer = Serializer::new();
    ffi_unwrap!(
        serializer.write_leb128_u64(results.len() as u64),
        "error serializing length",
        ErrorCode::Serialization.into()
    );
    for (keyword, locations) in results {
        ffi_unwrap!(
            serializer.write_vec(&keyword),
            "error serializing keyword",
            ErrorCode::Serialization.into()
        );
        let serialized_location_set = ffi_unwrap!(
            serialize_location_set(&locations),
            "error serializing set",
            ErrorCode::Serialization.into()
        );
        ffi_unwrap!(
            serializer.write_array(&serialized_location_set),
            "error serializing locations",
            ErrorCode::Serialization.into()
        );
    }
    let serialized_uids = serializer.finalize();

    ffi_write_bytes!("search results", &serialized_uids, results_ptr, results_len);
}

/// Adds the given associations to the index.
///
/// # Parameters
///
/// - `results`         : (output) list of new keywords added to the index
/// - `findex_handle`   : Findex handle on the instance cache
/// - `associations`    : map of values to sets of keywords
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_add(
    results_ptr: *mut u8,
    results_len: *mut i32,
    findex_handle: i32,
    associations_ptr: *const u8,
    associations_len: i32,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init();

    let associations_bytes = ffi_read_bytes!("associations", associations_ptr, associations_len);
    let associations = IndexedValueToKeywordsMap::from(ffi_unwrap!(
        deserialize_indexed_values(associations_bytes),
        "failed deserialize indexed values (associations)",
        ErrorCode::Serialization.into()
    ));

    let output_size = get_upsert_output_size(&associations);
    if *results_len < output_size as i32 {
        set_last_error(FfiError::Generic(format!(
            "The pre-allocated add results buffer is too small; need {} bytes, allocated {}",
            output_size, results_len as i32
        )));
        *results_len = output_size as i32;
        return ErrorCode::BufferTooSmall.into();
    }

    let cache = FINDEX_INSTANCES
        .lock()
        .expect("Findex instance cache lock poisoned.");

    let (key, label, findex) = ffi_unwrap!(
        cache
            .get(&findex_handle)
            .ok_or_else(|| format!("no matching instance for handle {findex_handle}")),
        "cannot get a hold on the Findex instance",
        ErrorCode::Findex.into()
    );

    trace!("instantiated Findex: {findex:?}");

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    let res = rt.block_on(findex.add(key, label, associations));

    let new_keywords = match res {
        Ok(new_keywords) => new_keywords,
        Err(FindexError::Callback(BackendError::Ffi(msg, code))) => {
            set_last_error(FfiError::Generic(format!(
                "backend error during `add` operation: {msg}"
            )));
            return code.into();
        }
        Err(e) => {
            set_last_error(FfiError::Generic(format!("findex `add` error: {e}")));
            return ErrorCode::Findex.into();
        }
    };

    // Serialize the results.
    let serialized_keywords = ffi_unwrap!(
        serialize_keyword_set(&new_keywords),
        "serialize new keywords",
        ErrorCode::Serialization.into()
    );

    ffi_write_bytes!(
        "add results",
        &serialized_keywords,
        results_ptr,
        results_len
    );
}

/// Removes the given associations from the index.
///
/// # Parameters
///
/// - `results`         : Returns the list of new keywords added to the index
/// - `findex_handle`   : Findex handle on the instance cache
/// - `associations`    : map of values to sets of keywords
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_delete(
    results_ptr: *mut u8,
    results_len: *mut i32,
    findex_handle: i32,
    associations_ptr: *const u8,
    associations_len: i32,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init();

    let associations_bytes = ffi_read_bytes!("associations", associations_ptr, associations_len);
    let associations = IndexedValueToKeywordsMap::from(ffi_unwrap!(
        deserialize_indexed_values(associations_bytes),
        "failed deserialize indexed values (associations)",
        ErrorCode::Serialization.into()
    ));

    let output_size = get_upsert_output_size(&associations);
    if *results_len < output_size as i32 {
        set_last_error(FfiError::Generic(format!(
            "The pre-allocated add results buffer is too small; need {} bytes, allocated {}",
            output_size, results_len as i32
        )));
        *results_len = output_size as i32;
        return ErrorCode::BufferTooSmall.into();
    }

    let cache = FINDEX_INSTANCES
        .lock()
        .expect("Findex instance cache lock poisoned.");

    let (key, label, findex) = ffi_unwrap!(
        cache
            .get(&findex_handle)
            .ok_or_else(|| format!("no matching instance for handle {findex_handle}")),
        "cannot get a hold on the Findex instance",
        ErrorCode::Findex.into()
    );

    trace!("instantiated Findex: {findex:?}");

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    let res = rt.block_on(findex.delete(key, label, associations));

    let new_keywords = match res {
        Ok(new_keywords) => new_keywords,
        Err(FindexError::Callback(BackendError::Ffi(msg, code))) => {
            set_last_error(FfiError::Generic(format!(
                "backend error during `delete` operation: {msg}"
            )));
            return code.into();
        }
        Err(e) => {
            set_last_error(FfiError::Generic(format!("findex `delete` error: {e}")));
            return ErrorCode::Findex.into();
        }
    };

    // Serialize the results.
    let serialized_keywords = ffi_unwrap!(
        serialize_keyword_set(&new_keywords),
        "serialize new keywords",
        ErrorCode::Serialization.into()
    );

    ffi_write_bytes!(
        "delete results",
        &serialized_keywords,
        results_ptr,
        results_len
    );
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
/// - `findex_handle`           : Findex handle on the instance cache
/// - `new_key`                 : new Findex key
/// - `new_label`               : public information used to derive UIDs
/// - `n_compact_to_full`       : see below
/// - `filter_obsolete_data`    : callback used to filter out obsolete data
///   among indexed data
///
/// `n_compact_to_full`: if you compact the
/// indexes every night this is the number of days to wait before
/// being sure that a big portion of the indexes were checked
/// (see the coupon problem to understand why it's not 100% sure)

/// # Safety
///
/// Cannot be safe since using FFI.
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_compact(
    findex_handle: i32,
    new_key_ptr: *const u8,
    new_key_len: i32,
    new_label_ptr: *const u8,
    new_label_len: i32,
    n_compact_to_full: u32,
    filter_obsolete_data: FilterObsoleteData,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init();

    let filter = |locations: HashSet<Location>| async {
        let move_locations = locations;
        let bytes = serialize_location_set(&move_locations)
            .map_err(|e| format!("error serializing locations: {e}"))?;
        let mut res = vec![0; bytes.len()];
        let mut res_length = res.len() as u32;
        let err = (filter_obsolete_data)(
            res.as_mut_ptr(),
            &mut res_length,
            bytes.as_ptr(),
            bytes.len() as u32,
        );

        if err != 0 {
            set_last_error(FfiError::Generic(format!("filter callback error: {err}")));
            return Err(String::from("Filter error."));
        }

        deserialize_location_set(&res)
            .map_err(|e| format!("error deserializing filtered locations: {e}"))
    };

    let new_key_bytes = ffi_read_bytes!("new key", new_key_ptr, new_key_len);
    let new_key = ffi_unwrap!(
        SymmetricKey::try_from_slice(new_key_bytes),
        "error deserializing new findex key",
        ErrorCode::Serialization.into()
    );

    let new_label_bytes = ffi_read_bytes!("new label", new_label_ptr, new_label_len);
    let new_label = Label::from(new_label_bytes);

    let mut cache = FINDEX_INSTANCES
        .lock()
        .expect("Findex instance cache lock poisoned.");

    let (old_key, old_label, findex) = ffi_unwrap!(
        cache
            .get_mut(&findex_handle)
            .ok_or_else(|| format!("no matching instance for handle {findex_handle}")),
        "cannot get a hold on the Findex instance",
        ErrorCode::Findex.into()
    );

    let rt = ffi_unwrap!(
        tokio::runtime::Runtime::new(),
        "error creating Tokio runtime"
    );

    trace!("instantiated Findex: {findex:?}");
    let res = rt.block_on(findex.compact(
        old_key,
        &new_key,
        old_label,
        &new_label,
        n_compact_to_full as usize,
        &filter,
    ));

    match res {
        Err(FindexError::Callback(BackendError::Ffi(msg, code))) => {
            set_last_error(FfiError::Generic(format!(
                "backend error during `compact` operation: {msg}"
            )));
            code.into()
        }
        Err(e) => {
            set_last_error(FfiError::Generic(format!("findex `compact` error: {e}")));
            ErrorCode::Findex.into()
        }
        Ok(()) => {
            *old_key = new_key;
            *old_label = new_label;
            ErrorCode::Success.into()
        }
    }
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
#[no_mangle]
#[tracing::instrument(ret, skip_all)]
pub unsafe extern "C" fn h_generate_new_token(
    token_ptr: *mut u8,
    token_len: *mut i32,
    index_id_ptr: *const i8,
    fetch_entries_seed_ptr: *const u8,
    fetch_entries_seed_len: i32,
    fetch_chains_seed_ptr: *const u8,
    fetch_chains_seed_len: i32,
    upsert_entries_seed_ptr: *const u8,
    upsert_entries_seed_len: i32,
    insert_chains_seed_ptr: *const u8,
    insert_chains_seed_len: i32,
) -> i32 {
    #[cfg(debug_assertions)]
    log_init();

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

    let mut seeds = HashMap::new();
    seeds.insert(
        CallbackPrefix::FetchEntry,
        ffi_unwrap!(
            SymmetricKey::try_from_slice(fetch_entries_seed),
            "fetch_entries_seed is of wrong size"
        ),
    );
    seeds.insert(
        CallbackPrefix::FetchChain,
        ffi_unwrap!(
            SymmetricKey::try_from_slice(fetch_chains_seed),
            "fetch_chains_seed is of wrong size"
        ),
    );
    seeds.insert(
        CallbackPrefix::Upsert,
        ffi_unwrap!(
            SymmetricKey::try_from_slice(upsert_entries_seed),
            "upsert_entries_seed is of wrong size"
        ),
    );
    seeds.insert(
        CallbackPrefix::Insert,
        ffi_unwrap!(
            SymmetricKey::try_from_slice(insert_chains_seed),
            "insert_chains_seed is of wrong size"
        ),
    );

    let mut rng = CsRng::from_entropy();
    let findex_key = SymmetricKey::new(&mut rng);

    let token = ffi_unwrap!(
        AuthorizationToken::new(index_id, findex_key, seeds),
        "generate authorization token"
    );

    ffi_write_bytes!(
        "search results",
        token.to_string().as_bytes(),
        token_ptr,
        token_len
    );
}

/// Re-export the `cosmian_ffi` `h_get_error` function to clients with the old
/// `get_last_error` name The `h_get_error` is available inside the final lib
/// (but tools like `ffigen` seems to not parse it…) Maybe we can find a
/// solution by changing the function name inside the clients.
///
/// # Safety
///
/// Cannot be safe since using FFI.
#[no_mangle]
pub unsafe extern "C" fn get_last_error(error_ptr: *mut i8, error_len: *mut i32) -> i32 {
    h_get_error(error_ptr, error_len)
}
