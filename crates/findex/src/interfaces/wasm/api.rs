//! Defines the Findex WASM API.

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use cosmian_crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, FixedSizeCBytes, RandomFixedSizeCBytes, SymmetricKey,
};
use cosmian_findex::{Data, IndexedValue, Keyword, Label};
use js_sys::{Array, Function, Promise, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::types::InterruptInput;
use crate::{
    db_interfaces::{
        custom::wasm::WasmCallbacks,
        rest::{AuthorizationToken, CallbackPrefix},
    },
    interfaces::wasm::{
        types::{ArrayOfKeywords, Filter, IndexedData, IndexedValuesAndKeywords, SearchResults},
        WasmError,
    },
    Configuration, InstantiatedFindex,
};

#[wasm_bindgen]
pub struct WasmFindex(InstantiatedFindex);

#[wasm_bindgen]
impl WasmFindex {
    /// Instantiates a Findex object from custom DB interfaces using the given
    /// callbacks.
    pub async fn new_with_custom_interface(
        entry_callbacks: WasmCallbacks,
        chain_callbacks: WasmCallbacks,
    ) -> Result<WasmFindex, JsError> {
        let config = Configuration::Wasm(entry_callbacks, chain_callbacks);
        InstantiatedFindex::new(config)
            .await
            .map(Self)
            .map_err(WasmError::from)
            .map_err(JsError::from)
    }

    /// Instantiates a Findex object using REST interfaces, using the given token
    /// and URLs.
    pub async fn new_with_rest_interface(
        token: String,
        entry_url: String,
        chain_url: String,
    ) -> Result<WasmFindex, JsError> {
        let config =
            Configuration::Rest(AuthorizationToken::from_str(&token)?, entry_url, chain_url);

        InstantiatedFindex::new(config)
            .await
            .map(Self)
            .map_err(WasmError::from)
            .map_err(JsError::from)
    }
}

#[wasm_bindgen]
impl WasmFindex {
    /// Searches this Findex instance for the given keywords.
    ///
    /// The interrupt is called at each search graph level with the level's
    /// results and allows interrupting the search.
    pub async fn search(
        &self,
        key: Uint8Array,
        label: String,
        keywords: ArrayOfKeywords,
        interrupt: Option<Function>,
    ) -> Result<SearchResults, JsError> {
        let key = SymmetricKey::try_from_slice(&key.to_vec()).map_err(|e| {
            WasmError(format!(
                "Findex search: While parsing key for Findex search, {e}"
            ))
        })?;

        let label = Label::from(label.as_str());

        let keywords = Array::from(&JsValue::from(keywords))
            .iter()
            .map(|word| Keyword::from(Uint8Array::new(&word).to_vec()))
            .collect::<HashSet<_>>();

        let user_interrupt = |res: HashMap<Keyword, HashSet<IndexedValue<Keyword, Data>>>| async {
            if let Some(interrupt) = &interrupt {
                let res = <InterruptInput>::try_from(res).map_err(|e| {
                    format!(
                        "Findex search: failed converting input of user interrupt into Js object: \
                     {e:?}"
                    )
                })?;
                let res = interrupt
                    .call1(&JsValue::null(), &res)
                    .map_err(|e| format!("failed calling user interrupt: {e:?}"))?;
                let interruption_flag =
                    JsFuture::from(Promise::resolve(&res)).await.map_err(|e| {
                        format!(
                    "Findex search: failed getting the promised results from user interrupt: {e:?}"
                )
                    })?;
                interruption_flag.as_bool().ok_or_else(|| {
                    format!(
                    "Findex search: user interrupt does not return a boolean value: {interrupt:?}"
                )
                })
            } else {
                Ok(false)
            }
        };

        let res = self
            .0
            .search(&key, &label, keywords.into(), &user_interrupt)
            .await?;

        <SearchResults>::try_from(&res).map_err(JsError::from)
    }

    /// Add the given values to this Findex index for the corresponding
    /// keywords.
    pub async fn add(
        &self,
        key: Uint8Array,
        label: String,
        additions: IndexedValuesAndKeywords,
    ) -> Result<ArrayOfKeywords, JsError> {
        log::info!("add: entering");
        let key = SymmetricKey::try_from_slice(&key.to_vec())
            .map_err(|e| WasmError(format!("Findex add: failed parsing key: {e}")))?;
        let label = Label::from(label.as_str());
        let additions =
            <HashMap<IndexedValue<Keyword, Data>, HashSet<Keyword>>>::try_from(&additions)
                .map_err(|e| {
                    WasmError(format!(
                        "Findex add: failed parsing additions from WASM: {e:?}"
                    ))
                })?;
        log::info!("add: key, label and additions correctly parsed");

        let keywords = self
            .0
            .add(&key, &label, additions.into())
            .await
            .map_err(|e| {
                WasmError(format!(
                    "Findex add: failed adding data to the index: {e:?}"
                ))
            })?;

        log::info!("add: exiting successfully: keywords: {}", keywords);
        Ok(<ArrayOfKeywords>::from(&keywords))
    }

    /// Remove the given values from this Findex index for the corresponding
    /// keywords.
    pub async fn delete(
        &self,
        key: Uint8Array,
        label: String,
        deletions: IndexedValuesAndKeywords,
    ) -> Result<ArrayOfKeywords, JsError> {
        let key = SymmetricKey::try_from_slice(&key.to_vec())
            .map_err(|e| WasmError(format!("Findex delete: failed parsing Findex key: {e}")))?;
        let label = Label::from(label.as_str());
        let deletions =
            <HashMap<IndexedValue<Keyword, Data>, HashSet<Keyword>>>::try_from(&deletions)
                .map_err(|e| {
                    WasmError(format!(
                        "Findex delete: failed parsing additions from WASM: {e:?}"
                    ))
                })?;

        let res = self
            .0
            .delete(&key, &label, deletions.into())
            .await
            .map_err(|e| {
                WasmError(format!(
                    "Findex delete: failed adding data to the index: {e:?}"
                ))
            })?;

        Ok(<ArrayOfKeywords>::from(&res))
    }

    pub async fn compact(
        &self,
        old_key: Uint8Array,
        new_key: Uint8Array,
        old_label: String,
        new_label: String,
        compacting_rate: f32,
        data_filter: Option<Filter>,
    ) -> Result<(), JsError> {
        let old_key = SymmetricKey::try_from_slice(&old_key.to_vec())
            .map_err(|e| WasmError(format!("Findex compact: failed parsing old key: {e}")))?;
        let new_key = SymmetricKey::try_from_slice(&new_key.to_vec())
            .map_err(|e| WasmError(format!("Findex compact: failed parsing new key: {e}")))?;
        let old_label = Label::from(old_label.as_str());
        let new_label = Label::from(new_label.as_str());
        let compacting_rate = compacting_rate as usize;

        let data_filter = |data: HashSet<Data>| async {
            if let Some(data_filter) = &data_filter {
                // This is necessary to take ownership of the `data` parameter and avoid using
                // the `move` semantic.
                let moved_data = data;
                let data = <IndexedData>::from(&moved_data);
                let js_function = Function::from(JsValue::from(data_filter));
                let promise =
                    Promise::resolve(&js_function.call1(&JsValue::null(), &data).map_err(|e| {
                        format!("Findex compact: failed calling the obsolete data filter: {e:?}")
                    })?);
                let filtered_data = JsFuture::from(promise).await.map_err(|e| {
                    format!(
                    "Findex compact: failed getting the promised results from the obsolete data \
                     filter: {e:?}"
                )
                })?;
                let filtered_data = <HashSet<Data>>::try_from(IndexedData::from(filtered_data))
                    .map_err(|e| {
                        format!(
                        "Findex compact: failed converting Js array back to filtered data: {e:?}"
                    )
                    })?;
                Ok(filtered_data)
            } else {
                Ok(data)
            }
        };

        self.0
            .compact(
                &old_key,
                &new_key,
                &old_label,
                &new_label,
                compacting_rate as f64,
                &data_filter,
            )
            .await
            .map_err(|e| {
                JsError::from(WasmError(format!(
                    "Findex compact: failed compacting: {e:?}"
                )))
            })
    }
}

#[wasm_bindgen]
#[must_use]
#[derive(Debug, Clone)]
pub struct WasmToken(AuthorizationToken);

#[wasm_bindgen]
impl WasmToken {
    /// Generates a new random token for the given index. This token holds new
    /// authorization keys for all rights.
    pub fn random(index_id: String) -> Result<String, JsError> {
        let mut rng = CsRng::from_entropy();
        let findex_key = SymmetricKey::new(&mut rng);
        let seeds = (0..4)
            .map(|prefix_id| {
                (
                    CallbackPrefix::try_from(prefix_id).expect("prefix IDs are correct"),
                    SymmetricKey::new(&mut rng),
                )
            })
            .collect();

        Ok(Self(AuthorizationToken::new(index_id, findex_key, seeds)?)
            .0
            .to_string())
    }

    pub fn create(
        index_id: String,
        fetch_entries_key: Option<Uint8Array>,
        fetch_chains_key: Option<Uint8Array>,
        upsert_entries_key: Option<Uint8Array>,
        insert_chains_key: Option<Uint8Array>,
    ) -> Result<String, JsError> {
        let mut rng = CsRng::from_entropy();
        let findex_key = SymmetricKey::new(&mut rng);

        let mut seeds = HashMap::new();
        if let Some(key) = fetch_entries_key {
            let key = SymmetricKey::try_from_slice(key.to_vec().as_slice())?;
            seeds.insert(CallbackPrefix::FetchEntry, key);
        }
        if let Some(key) = fetch_chains_key {
            let key = SymmetricKey::try_from_slice(key.to_vec().as_slice())?;
            seeds.insert(CallbackPrefix::FetchChain, key);
        }
        if let Some(key) = upsert_entries_key {
            let key = SymmetricKey::try_from_slice(key.to_vec().as_slice())?;
            seeds.insert(CallbackPrefix::Upsert, key);
        }
        if let Some(key) = insert_chains_key {
            let key = SymmetricKey::try_from_slice(key.to_vec().as_slice())?;
            seeds.insert(CallbackPrefix::Insert, key);
        }

        let token = AuthorizationToken::new(index_id, findex_key, seeds)?;
        Ok(token.to_string())
    }

    /// Generates a new authentication token with the given permissions.
    ///
    /// # Error
    ///
    /// Returns an error if the requested permissions are higher than the ones
    /// associated to this token.
    pub fn generate_reduced_token_string(
        &self,
        is_read: bool,
        is_write: bool,
    ) -> Result<WasmToken, JsError> {
        let mut new_token: WasmToken = self.clone();
        new_token.0.reduce_permissions(is_read, is_write)?;
        Ok(new_token)
    }
}
