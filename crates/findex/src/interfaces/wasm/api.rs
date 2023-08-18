//! Defines the Findex WASM API.

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use cosmian_crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, FixedSizeCBytes, RandomFixedSizeCBytes, SymmetricKey,
};
use cosmian_findex::{IndexedValue, Keyword, Label, Location};
use js_sys::{Array, Function, Promise, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::types::InterruptInput;
use crate::{
    backends::{
        cloud::{CloudParameters, FindexToken},
        custom::wasm::WasmCallbacks,
        CallbackPrefix,
    },
    interfaces::wasm::{
        types::{ArrayOfKeywords, Filter, IndexedData, IndexedValuesAndKeywords, SearchResults},
        WasmError,
    },
    BackendConfiguration, InstantiatedFindex,
};

#[wasm_bindgen]
pub struct WasmFindex(InstantiatedFindex);

#[wasm_bindgen]
impl WasmFindex {
    /// Instantiates a Findex object from custom WASM backends using the given
    /// callbacks.
    pub async fn new_with_wasm_backend(
        entry_callbacks: WasmCallbacks,
        chain_callbacks: WasmCallbacks,
    ) -> Result<WasmFindex, JsError> {
        let config = BackendConfiguration::Wasm(entry_callbacks, chain_callbacks);
        InstantiatedFindex::new(config)
            .await
            .map(Self)
            .map_err(WasmError::from)
            .map_err(JsError::from)
    }

    /// Instantiates a Findex object using REST backends, using the given token
    /// and URL.
    pub async fn new_with_cloud_backend(
        token: String,
        url: Option<String>,
    ) -> Result<WasmFindex, JsError> {
        let config = BackendConfiguration::Cloud(
            CloudParameters::new(FindexToken::from_str(&token)?, url.clone()),
            CloudParameters::new(FindexToken::from_str(&token)?, url.clone()),
        );

        InstantiatedFindex::new(config)
            .await
            .map(Self)
            .map_err(WasmError::from)
            .map_err(JsError::from)
    }

    /// Searches this Findex instance for the given keywords.
    ///
    /// The interrupt is called at each search graph level with the level's
    /// results and allows interrupting the search.
    pub async fn search(
        &self,
        key: Uint8Array,
        label: Uint8Array,
        keywords: ArrayOfKeywords,
        interrupt: &Function,
    ) -> Result<SearchResults, JsError> {
        let key = SymmetricKey::try_from_slice(&key.to_vec()).map_err(|e| {
            WasmError(format!(
                "Findex search: While parsing key for Findex search, {e}"
            ))
        })?;

        let label = Label::from(label.to_vec());

        let keywords = Array::from(&JsValue::from(keywords))
            .iter()
            .map(|word| Keyword::from(Uint8Array::new(&word).to_vec()))
            .collect::<HashSet<_>>();

        let user_interrupt = |res: HashMap<Keyword, HashSet<IndexedValue<Keyword, Location>>>| async {
            let res = <InterruptInput>::try_from(res).map_err(|e| {
                format!(
                    "Findex search: failed converting input of user interrupt into Js object: \
                     {e:?}"
                )
            })?;
            let res = interrupt
                .call1(&JsValue::null(), &res)
                .map_err(|e| format!("failed calling user interrupt: {e:?}"))?;
            let interruption_flag = JsFuture::from(Promise::resolve(&res)).await.map_err(|e| {
                format!(
                    "Findex search: failed getting the promised results from user interrupt: {e:?}"
                )
            })?;
            interruption_flag.as_bool().ok_or_else(|| {
                format!(
                    "Findex search: user interrupt does not return a boolean value: {interrupt:?}"
                )
            })
        };

        let res = self
            .0
            .search(&key, &label, keywords.into(), &user_interrupt)
            .await?;

        <SearchResults>::try_from(&res.into()).map_err(JsError::from)
    }

    /// Add the given values to this Findex index for the corresponding
    /// keywords.
    pub async fn add(
        &self,
        key: Uint8Array,
        label: Uint8Array,
        additions: IndexedValuesAndKeywords,
    ) -> Result<ArrayOfKeywords, JsError> {
        let key = SymmetricKey::try_from_slice(&key.to_vec())
            .map_err(|e| WasmError(format!("Findex add: failed parsing key: {e}")))?;
        let label = Label::from(label.to_vec());
        let additions =
            <HashMap<IndexedValue<Keyword, Location>, HashSet<Keyword>>>::try_from(&additions)
                .map_err(|e| {
                    WasmError(format!(
                        "Findex add: failed parsing additions from WASM: {e:?}"
                    ))
                })?;

        let res = self
            .0
            .add(&key, &label, additions.into())
            .await
            .map_err(|e| {
                WasmError(format!(
                    "Findex add: failed adding data to the index: {e:?}"
                ))
            })?;

        <ArrayOfKeywords>::try_from(&res.into()).map_err(|e| {
            JsError::from(WasmError(format!(
                "Findex add: could not convert new keywords to Js array: {e:?}"
            )))
        })
    }

    /// Remove the given values from this Findex index for the corresponding
    /// keywords.
    pub async fn delete(
        &self,
        key: Uint8Array,
        label: Uint8Array,
        deletions: IndexedValuesAndKeywords,
    ) -> Result<ArrayOfKeywords, JsError> {
        let key = SymmetricKey::try_from_slice(&key.to_vec())
            .map_err(|e| WasmError(format!("Findex delete: failed parsing Findex key: {e}")))?;
        let label = Label::from(label.to_vec());
        let deletions =
            <HashMap<IndexedValue<Keyword, Location>, HashSet<Keyword>>>::try_from(&deletions)
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

        <ArrayOfKeywords>::try_from(&res.into()).map_err(|e| {
            JsError::from(WasmError(format!(
                "Findex delete: could not convert new keywords to Js array: {e:?}"
            )))
        })
    }

    pub async fn compact(
        &self,
        old_key: &Uint8Array,
        new_key: &Uint8Array,
        old_label: &Uint8Array,
        new_label: &Uint8Array,
        n_compact_to_full: u32,
        filter_obsolete_data: Filter,
    ) -> Result<(), JsError> {
        let old_key = SymmetricKey::try_from_slice(&old_key.to_vec())
            .map_err(|e| WasmError(format!("Findex compact: failed parsing old key: {e}")))?;
        let new_key = SymmetricKey::try_from_slice(&new_key.to_vec())
            .map_err(|e| WasmError(format!("Findex compact: failed parsing new key: {e}")))?;
        let old_label = Label::from(old_label.to_vec());
        let new_label = Label::from(new_label.to_vec());
        let n_compact_to_full = n_compact_to_full as usize;

        let filter = |data: HashSet<Location>| async {
            // This is necessary to take ownership of the `data` parameter and avoid using
            // the `move` semantic.
            let moved_data = data;
            let data = <IndexedData>::from(&moved_data);
            let js_function = Function::from(JsValue::from(&filter_obsolete_data));
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
            let filtered_data = <HashSet<Location>>::try_from(IndexedData::from(filtered_data))
                .map_err(|e| {
                    format!(
                        "Findex compact: failed converting Js array back to filtered data: {e:?}"
                    )
                })?;
            Ok(filtered_data)
        };

        self.0
            .compact(
                &old_key,
                &new_key,
                &old_label,
                &new_label,
                n_compact_to_full,
                &filter,
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
struct WasmToken(FindexToken);

#[wasm_bindgen]
impl FindexToken {
    pub fn random(index_id: u32) -> String {
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

        Self::new(index_id, findex_key, seeds).to_string()
    }
}
