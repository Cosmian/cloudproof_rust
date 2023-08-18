use std::{
    collections::{HashMap, HashSet},
    future::Future,
};

use cosmian_findex::{
    ChainTable, DxEnc, EntryTable, Error as FindexError, Findex, Index, IndexedValue,
    IndexedValueToKeywordsMap, Keyword, KeywordToDataMap, Keywords, Label, Location, UserKey,
    ENTRY_LENGTH, LINK_LENGTH,
};

#[cfg(feature = "backend-ffi")]
use crate::backends::custom::ffi::{FfiChainBackend, FfiEntryBackend};
#[cfg(feature = "backend-python")]
use crate::backends::custom::python::{PythonChainBackend, PythonEntryBackend};
#[cfg(feature = "backend-wasm")]
use crate::backends::custom::wasm::{WasmChainBackend, WasmEntryBackend};
#[cfg(feature = "backend-redis")]
use crate::backends::redis::{RedisChainBackend, RedisEntryBackend};
#[cfg(feature = "backend-rest")]
use crate::backends::rest::{RestChainBackend, RestEntryBackend, RestParameters};
#[cfg(feature = "backend-sqlite")]
use crate::backends::sqlite::{SqlChainBackend, SqlEntryBackend};
use crate::{backends::BackendError, BackendConfiguration};

/// Wrapper around Findex instantiations used for static dispatch.
#[derive(Debug)]
pub enum InstantiatedFindex {
    #[cfg(feature = "backend-sqlite")]
    Sqlite(
        Findex<
            BackendError,
            EntryTable<ENTRY_LENGTH, SqlEntryBackend>,
            ChainTable<LINK_LENGTH, SqlChainBackend>,
        >,
    ),

    #[cfg(feature = "backend-redis")]
    Redis(
        Findex<
            BackendError,
            EntryTable<ENTRY_LENGTH, RedisEntryBackend>,
            ChainTable<LINK_LENGTH, RedisChainBackend>,
        >,
    ),

    #[cfg(feature = "backend-ffi")]
    Ffi(
        Findex<
            BackendError,
            EntryTable<ENTRY_LENGTH, FfiEntryBackend>,
            ChainTable<LINK_LENGTH, FfiChainBackend>,
        >,
    ),

    #[cfg(feature = "backend-python")]
    Python(
        Findex<
            BackendError,
            EntryTable<ENTRY_LENGTH, PythonEntryBackend>,
            ChainTable<LINK_LENGTH, PythonChainBackend>,
        >,
    ),
    #[cfg(feature = "backend-wasm")]
    Wasm(
        Findex<
            BackendError,
            EntryTable<ENTRY_LENGTH, WasmEntryBackend>,
            ChainTable<LINK_LENGTH, WasmChainBackend>,
        >,
    ),

    #[cfg(feature = "backend-rest")]
    Rest(
        Findex<
            BackendError,
            EntryTable<ENTRY_LENGTH, RestEntryBackend>,
            ChainTable<LINK_LENGTH, RestChainBackend>,
        >,
    ),
}

impl InstantiatedFindex {
    /// Wrapper around Findex [`new`](Index::new) for static dispatch.
    pub async fn new(config: BackendConfiguration) -> Result<Self, BackendError> {
        let findex = match config {
            #[cfg(feature = "backend-sqlite")]
            BackendConfiguration::Sqlite(entry_params, chain_params) => Self::Sqlite(Findex::new(
                EntryTable::setup(SqlEntryBackend::new(&entry_params)?),
                ChainTable::setup(SqlChainBackend::new(&chain_params)?),
            )),

            #[cfg(feature = "backend-redis")]
            BackendConfiguration::Redis(entry_params, chain_params) => Self::Redis(Findex::new(
                EntryTable::setup(RedisEntryBackend::connect(&entry_params).await?),
                ChainTable::setup(RedisChainBackend::connect(&chain_params).await?),
            )),

            #[cfg(feature = "backend-rest")]
            BackendConfiguration::Rest(token, url) => Self::Rest(Findex::new(
                EntryTable::setup(RestEntryBackend::new(RestParameters::new(
                    token.clone(),
                    Some(url.clone()),
                ))),
                ChainTable::setup(RestChainBackend::new(RestParameters::new(token, Some(url)))),
            )),

            #[cfg(feature = "backend-ffi")]
            BackendConfiguration::Ffi(entry_params, chain_params) => Self::Ffi(Findex::new(
                EntryTable::setup(FfiEntryBackend::new(entry_params)),
                ChainTable::setup(FfiChainBackend::new(chain_params)),
            )),

            #[cfg(feature = "backend-python")]
            BackendConfiguration::Python(entry_params, chain_params) => Self::Python(Findex::new(
                EntryTable::setup(PythonEntryBackend::new(entry_params)),
                ChainTable::setup(PythonChainBackend::new(chain_params)),
            )),

            #[cfg(feature = "backend-wasm")]
            BackendConfiguration::Wasm(entry_params, chain_params) => Self::Wasm(Findex::new(
                EntryTable::setup(WasmEntryBackend::new(entry_params)),
                ChainTable::setup(WasmChainBackend::new(chain_params)),
            )),
        };

        Ok(findex)
    }

    /// Wrapper around Findex [`keygen`](Index::keygen) for static dispatch.
    pub fn keygen(&self) -> UserKey {
        match self {
            #[cfg(feature = "backend-sqlite")]
            Self::Sqlite(findex) => findex.keygen(),
            #[cfg(feature = "backend-redis")]
            Self::Redis(findex) => findex.keygen(),
            #[cfg(feature = "backend-ffi")]
            Self::Ffi(findex) => findex.keygen(),
            #[cfg(feature = "backend-python")]
            Self::Python(findex) => findex.keygen(),
            #[cfg(feature = "backend-wasm")]
            Self::Wasm(findex) => findex.keygen(),
            #[cfg(feature = "backend-rest")]
            Self::Rest(findex) => findex.keygen(),
        }
    }

    /// Wrapper around Findex [`search`](Index::search) for static dispatch.
    pub async fn search<
        F: Future<Output = Result<bool, String>>,
        Interrupt: Fn(HashMap<Keyword, HashSet<IndexedValue<Keyword, Location>>>) -> F,
    >(
        &self,
        key: &UserKey,
        label: &Label,
        keywords: Keywords,
        interrupt: &Interrupt,
    ) -> Result<KeywordToDataMap, FindexError<BackendError>> {
        match self {
            #[cfg(feature = "backend-rest")]
            Self::Rest(findex) => findex.search(key, label, keywords, interrupt).await,
            #[cfg(feature = "backend-ffi")]
            Self::Ffi(findex) => findex.search(key, label, keywords, interrupt).await,
            #[cfg(feature = "backend-python")]
            Self::Python(findex) => findex.search(key, label, keywords, interrupt).await,
            #[cfg(feature = "backend-sqlite")]
            Self::Sqlite(findex) => findex.search(key, label, keywords, interrupt).await,
            #[cfg(feature = "backend-redis")]
            Self::Redis(findex) => findex.search(key, label, keywords, interrupt).await,
            #[cfg(feature = "backend-wasm")]
            Self::Wasm(findex) => findex.search(key, label, keywords, interrupt).await,
        }
    }

    /// Wrapper around Findex [`add`](Index::add) for static dispatch.
    pub async fn add(
        &self,
        key: &UserKey,
        label: &Label,
        additions: IndexedValueToKeywordsMap,
    ) -> Result<Keywords, FindexError<BackendError>> {
        match self {
            #[cfg(feature = "backend-sqlite")]
            Self::Sqlite(findex) => findex.add(key, label, additions).await,
            #[cfg(feature = "backend-redis")]
            Self::Redis(findex) => findex.add(key, label, additions).await,
            #[cfg(feature = "backend-ffi")]
            Self::Ffi(findex) => findex.add(key, label, additions).await,
            #[cfg(feature = "backend-python")]
            Self::Python(findex) => findex.add(key, label, additions).await,
            #[cfg(feature = "backend-wasm")]
            Self::Wasm(findex) => findex.add(key, label, additions).await,
            #[cfg(feature = "backend-rest")]
            Self::Rest(findex) => findex.add(key, label, additions).await,
        }
    }

    /// Wrapper around Findex [`delete`](Index::delete) for static dispatch.
    pub async fn delete(
        &self,
        key: &UserKey,
        label: &Label,
        deletions: IndexedValueToKeywordsMap,
    ) -> Result<Keywords, FindexError<BackendError>> {
        match self {
            #[cfg(feature = "backend-sqlite")]
            Self::Sqlite(findex) => findex.delete(key, label, deletions).await,
            #[cfg(feature = "backend-redis")]
            Self::Redis(findex) => findex.delete(key, label, deletions).await,
            #[cfg(feature = "backend-ffi")]
            Self::Ffi(findex) => findex.delete(key, label, deletions).await,
            #[cfg(feature = "backend-python")]
            Self::Python(findex) => findex.delete(key, label, deletions).await,
            #[cfg(feature = "backend-wasm")]
            Self::Wasm(findex) => findex.delete(key, label, deletions).await,
            #[cfg(feature = "backend-rest")]
            Self::Rest(findex) => findex.delete(key, label, deletions).await,
        }
    }

    /// Wrapper around Findex [`compact`](Findex::compact) for static dispatch.
    pub async fn compact<
        F: Future<Output = Result<HashSet<Location>, String>>,
        Filter: Fn(HashSet<Location>) -> F,
    >(
        &self,
        old_key: &UserKey,
        new_key: &UserKey,
        old_label: &Label,
        new_label: &Label,
        n_compact_to_full: usize,
        filter_obsolete_data: &Filter,
    ) -> Result<(), FindexError<BackendError>> {
        match self {
            #[cfg(feature = "backend-sqlite")]
            Self::Sqlite(findex) => {
                findex
                    .compact(
                        old_key,
                        new_key,
                        old_label,
                        new_label,
                        n_compact_to_full,
                        filter_obsolete_data,
                    )
                    .await
            }
            #[cfg(feature = "backend-redis")]
            Self::Redis(findex) => {
                findex
                    .compact(
                        old_key,
                        new_key,
                        old_label,
                        new_label,
                        n_compact_to_full,
                        filter_obsolete_data,
                    )
                    .await
            }
            #[cfg(feature = "backend-ffi")]
            Self::Ffi(findex) => {
                findex
                    .compact(
                        old_key,
                        new_key,
                        old_label,
                        new_label,
                        n_compact_to_full,
                        filter_obsolete_data,
                    )
                    .await
            }
            #[cfg(feature = "backend-python")]
            Self::Python(findex) => {
                findex
                    .compact(
                        old_key,
                        new_key,
                        old_label,
                        new_label,
                        n_compact_to_full,
                        filter_obsolete_data,
                    )
                    .await
            }
            #[cfg(feature = "backend-wasm")]
            Self::Wasm(findex) => {
                findex
                    .compact(
                        old_key,
                        new_key,
                        old_label,
                        new_label,
                        n_compact_to_full,
                        filter_obsolete_data,
                    )
                    .await
            }
            #[cfg(feature = "backend-rest")]
            Self::Rest(findex) => {
                findex
                    .compact(
                        old_key,
                        new_key,
                        old_label,
                        new_label,
                        n_compact_to_full,
                        filter_obsolete_data,
                    )
                    .await
            }
        }
    }
}
