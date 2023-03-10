//! Defines the Findex WASM API.

#[cfg(feature = "cloud")]
use std::str::FromStr;
use std::{collections::HashSet, num::NonZeroUsize};

use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_findex::{
    parameters::{MASTER_KEY_LENGTH, SECURE_FETCH_CHAINS_BATCH_SIZE},
    FindexSearch, FindexUpsert, KeyingMaterial, Keyword, Label,
};
use js_sys::{Array, Uint8Array};
use wasm_bindgen::prelude::*;

use super::core::{Fetch, FindexUser, Insert, Progress, Upsert};
#[cfg(feature = "cloud")]
use crate::cloud::{FindexCloud, Token, SIGNATURE_SEED_LENGTH};
use crate::{
    wasm_bindgen::core::{
        search_results_to_js, to_indexed_values_to_keywords, ArrayOfKeywords,
        IndexedValuesAndWords, SearchResults,
    },
    MAX_RESULTS_PER_KEYWORD,
};

/// See [`FindexSearch::search()`](crate::core::FindexSearch::search).
///
/// # Parameters
///
/// - `master_key`              : master key
/// - `label_bytes`             : bytes of the public label used for hashing
/// - `keywords`                : list of keyword bytes to search
/// - `max_results_per_keyword` : maximum results returned for a keyword
/// - `max_depth`               : maximum recursion level allowed
/// - `fetch_chains_batch_size` : increase this value to improve performances
///   but decrease security by batching fetch chains calls
/// - `progress`                : progress callback
/// - `fetch_entries`           : callback to fetch from the Entry Table
/// - `fetch_chains`            : callback to fetch from the Chain Table
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn webassembly_search(
    master_key: Uint8Array,
    label_bytes: Uint8Array,
    keywords: ArrayOfKeywords,
    max_results_per_keyword: i32,
    max_depth: i32,
    fetch_chains_batch_size: i32,
    progress: Progress,
    fetch_entry: Fetch,
    fetch_chain: Fetch,
) -> Result<SearchResults, JsValue> {
    let master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(&master_key.to_vec())
        .map_err(|e| JsValue::from(format!("While parsing master key for Findex search, {e}")))?;
    let label = Label::from(label_bytes.to_vec());

    let keywords = Array::from(&JsValue::from(keywords))
        .iter()
        .map(|word| Keyword::from(Uint8Array::new(&word).to_vec()))
        .collect::<HashSet<_>>();

    let max_results_per_keyword = usize::try_from(max_results_per_keyword)
        .ok()
        .and_then(NonZeroUsize::new)
        .unwrap_or(MAX_RESULTS_PER_KEYWORD);

    let fetch_chains_batch_size = usize::try_from(fetch_chains_batch_size)
        .ok()
        .and_then(NonZeroUsize::new)
        .unwrap_or(SECURE_FETCH_CHAINS_BATCH_SIZE);

    let mut wasm_search = FindexUser {
        progress: Some(progress),
        fetch_entry: Some(fetch_entry),
        fetch_chain: Some(fetch_chain),
        upsert_entry: None,
        insert_chain: None,
    };

    let results = wasm_search
        .search(
            &keywords,
            &master_key,
            &label,
            max_results_per_keyword.into(),
            max_depth.try_into().unwrap_or(usize::MAX),
            fetch_chains_batch_size,
            0,
        )
        .await
        .map_err(|e| JsValue::from(format!("During Findex search: {e}")))?;

    search_results_to_js(&results)
}

/// See [`FindexUpsert::upsert()`](crate::core::FindexUpsert::upsert).
///
/// # Parameters
///
/// - `master_key`                  : master key
/// - `label_bytes`                 : public label used for hashing
/// - `indexed_value_to_keywords`   : map of `IndexedValue`s to `Keyword` bytes
/// - `fetch_entries`               : the callback to fetch from the entry table
/// - `upsert_entries`              : the callback to upsert in the entry table
/// - `insert_chains`               : the callback to insert in the chain table
#[wasm_bindgen]
pub async fn webassembly_upsert(
    master_key: Uint8Array,
    label_bytes: Uint8Array,
    indexed_values_to_keywords: IndexedValuesAndWords,
    fetch_entry: Fetch,
    upsert_entry: Upsert,
    insert_chain: Insert,
) -> Result<(), JsValue> {
    let master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(&master_key.to_vec())
        .map_err(|e| JsValue::from(format!("While parsing master key for Findex upsert, {e}")))?;
    let label = Label::from(label_bytes.to_vec());
    let indexed_values_to_keywords = wasm_unwrap!(
        to_indexed_values_to_keywords(&indexed_values_to_keywords),
        "error converting to indexed values and keywords"
    );

    let mut wasm_upsert = FindexUser {
        progress: None,
        fetch_entry: Some(fetch_entry),
        fetch_chain: None,
        upsert_entry: Some(upsert_entry),
        insert_chain: Some(insert_chain),
    };
    wasm_upsert
        .upsert(indexed_values_to_keywords, &master_key, &label)
        .await
        .map_err(|e| JsValue::from(format!("During Findex upsert: {e}")))
}

/// See [`FindexSearch::search()`](crate::core::FindexSearch::search).
///
/// # Parameters
///
/// - `master_key`              : master key
/// - `label_bytes`             : bytes of the public label used for hashing
/// - `keywords`                : list of keyword bytes to search
/// - `max_results_per_keyword` : maximum results returned for a keyword
/// - `max_depth`               : maximum recursion level allowed
/// - `fetch_chains_batch_size` : increase this value to improve performances
///   but
/// - `base_url`                : base URL for Findex Cloud (with http prefix
///   and port if required). If null, use the default Findex Cloud server.
#[cfg(feature = "cloud")]
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn webassembly_search_cloud(
    token: String,
    label_bytes: Uint8Array,
    keywords: ArrayOfKeywords,
    max_results_per_keyword: i32,
    max_depth: i32,
    fetch_chains_batch_size: i32,
    base_url: Option<String>,
) -> Result<SearchResults, JsValue> {
    let mut findex_cloud = FindexCloud::new(&token, base_url)?;
    let master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(
        findex_cloud.token.findex_master_key.as_ref(),
    )
    .map_err(|e| JsValue::from(format!("While parsing master key for Findex upsert, {e}")))?;

    let label = Label::from(label_bytes.to_vec());

    let keywords = Array::from(&JsValue::from(keywords))
        .iter()
        .map(|word| Keyword::from(Uint8Array::new(&word).to_vec()))
        .collect::<HashSet<_>>();

    let max_results_per_keyword = usize::try_from(max_results_per_keyword)
        .ok()
        .and_then(NonZeroUsize::new)
        .unwrap_or(MAX_RESULTS_PER_KEYWORD);

    let fetch_chains_batch_size = usize::try_from(fetch_chains_batch_size)
        .ok()
        .and_then(NonZeroUsize::new)
        .unwrap_or(SECURE_FETCH_CHAINS_BATCH_SIZE);

    let results = findex_cloud
        .search(
            &keywords,
            &master_key,
            &label,
            max_results_per_keyword.into(),
            max_depth.try_into().unwrap_or(usize::MAX),
            fetch_chains_batch_size,
            0,
        )
        .await
        .map_err(|e| JsValue::from(format!("During Findex search: {e}")))?;

    search_results_to_js(&results)
}

/// See [`FindexUpsert::upsert()`](crate::core::FindexUpsert::upsert).
///
/// # Parameters
///
/// - `token`                       : findex cloud token
/// - `label_bytes`                 : public label used for hashing
/// - `indexed_value_to_keywords`   : map of `IndexedValue`s to `Keyword` bytes
/// - `base_url`                : base URL for Findex Cloud (with http prefix
///   and port if required). If null, use the default Findex Cloud server.
#[cfg(feature = "cloud")]
#[wasm_bindgen]
pub async fn webassembly_upsert_cloud(
    token: String,
    label_bytes: Uint8Array,
    indexed_values_to_keywords: IndexedValuesAndWords,
    base_url: Option<String>,
) -> Result<(), JsValue> {
    let mut findex_cloud = FindexCloud::new(&token, base_url)?;

    let master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(
        findex_cloud.token.findex_master_key.as_ref(),
    )
    .map_err(|e| JsValue::from(format!("While parsing master key for Findex upsert, {e}")))?;
    let label = Label::from(label_bytes.to_vec());
    let indexed_values_to_keywords = wasm_unwrap!(
        to_indexed_values_to_keywords(&indexed_values_to_keywords),
        "error converting indexed values and keywords"
    );

    findex_cloud
        .upsert(indexed_values_to_keywords, &master_key, &label)
        .await
        .map_err(|e| JsValue::from(format!("During Findex Cloud upsert: {e}")))
}

/// Generate a new Findex Cloud token with reduced permissions
#[cfg(feature = "cloud")]
#[wasm_bindgen]
pub fn webassembly_derive_new_token(
    token: String,
    search: bool,
    index: bool,
) -> Result<String, JsValue> {
    let mut token = Token::from_str(&token)?;

    token.reduce_permissions(search, index)?;

    Ok(token.to_string())
}

/// Generate a new random Findex Cloud token
#[cfg(feature = "cloud")]
#[wasm_bindgen]
pub fn webassembly_generate_new_token(
    index_id: String,
    fetch_entries_seed: Uint8Array,
    fetch_chains_seed: Uint8Array,
    upsert_entries_seed: Uint8Array,
    insert_chains_seed: Uint8Array,
) -> Result<String, JsValue> {
    let token = Token::random_findex_master_key(
        index_id,
        uint8array_to_seed(fetch_entries_seed, "fetch_entries_seed")?,
        uint8array_to_seed(fetch_chains_seed, "fetch_chains_seed")?,
        uint8array_to_seed(upsert_entries_seed, "upsert_entries_seed")?,
        uint8array_to_seed(insert_chains_seed, "insert_chains_seed")?,
    )?;

    Ok(token.to_string())
}

#[cfg(feature = "cloud")]
fn uint8array_to_seed(
    seed: Uint8Array,
    debug_name: &str,
) -> Result<KeyingMaterial<SIGNATURE_SEED_LENGTH>, JsValue> {
    let key_material = wasm_unwrap!(
        KeyingMaterial::try_from_bytes(seed.to_vec().as_slice()),
        format!(
            "{debug_name} is of wrong size ({} received, {SIGNATURE_SEED_LENGTH} expected)",
            seed.length()
        )
    );
    Ok(key_material)
}
