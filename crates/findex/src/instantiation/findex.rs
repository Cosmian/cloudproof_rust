use std::{
    collections::{HashMap, HashSet},
    future::Future,
};

use cosmian_findex::{
    ChainTable, Data, DxEnc, EntryTable, Error as FindexError, Findex, Index, IndexedValue,
    IndexedValueToKeywordsMap, Keyword, KeywordToDataMap, Keywords, Label, UserKey, ENTRY_LENGTH,
    LINK_LENGTH,
};

#[cfg(feature = "ffi")]
use crate::db_interfaces::custom::ffi::{FfiChainBackend, FfiEntryBackend};
#[cfg(feature = "python")]
use crate::db_interfaces::custom::python::{PythonChainBackend, PythonEntryBackend};
#[cfg(feature = "wasm")]
use crate::db_interfaces::custom::wasm::{WasmChainBackend, WasmEntryBackend};
#[cfg(feature = "redis-interface")]
use crate::db_interfaces::redis::{RedisChainBackend, RedisEntryBackend};
#[cfg(feature = "rest-interface")]
use crate::db_interfaces::rest::{RestChainBackend, RestEntryBackend, RestParameters};
#[cfg(feature = "sqlite-interface")]
use crate::db_interfaces::sqlite::{SqlChainBackend, SqlEntryBackend};
use crate::{db_interfaces::DbInterfaceError, Configuration};

/// Wrapper around Findex instantiations used for static dispatch.
#[derive(Debug)]
pub enum InstantiatedFindex {
    #[cfg(feature = "sqlite-interface")]
    Sqlite(
        Findex<
            DbInterfaceError,
            EntryTable<ENTRY_LENGTH, SqlEntryBackend>,
            ChainTable<LINK_LENGTH, SqlChainBackend>,
        >,
    ),

    #[cfg(feature = "redis-interface")]
    Redis(
        Findex<
            DbInterfaceError,
            EntryTable<ENTRY_LENGTH, RedisEntryBackend>,
            ChainTable<LINK_LENGTH, RedisChainBackend>,
        >,
    ),

    #[cfg(feature = "ffi")]
    Ffi(
        Findex<
            DbInterfaceError,
            EntryTable<ENTRY_LENGTH, FfiEntryBackend>,
            ChainTable<LINK_LENGTH, FfiChainBackend>,
        >,
    ),

    #[cfg(feature = "python")]
    Python(
        Findex<
            DbInterfaceError,
            EntryTable<ENTRY_LENGTH, PythonEntryBackend>,
            ChainTable<LINK_LENGTH, PythonChainBackend>,
        >,
    ),
    #[cfg(feature = "wasm")]
    Wasm(
        Findex<
            DbInterfaceError,
            EntryTable<ENTRY_LENGTH, WasmEntryBackend>,
            ChainTable<LINK_LENGTH, WasmChainBackend>,
        >,
    ),

    #[cfg(feature = "rest-interface")]
    Rest(
        Findex<
            DbInterfaceError,
            EntryTable<ENTRY_LENGTH, RestEntryBackend>,
            ChainTable<LINK_LENGTH, RestChainBackend>,
        >,
    ),
}

impl InstantiatedFindex {
    /// Wrapper around Findex [`new`](Index::new) for static dispatch.
    pub async fn new(config: Configuration) -> Result<Self, DbInterfaceError> {
        let findex = match config {
            #[cfg(feature = "sqlite-interface")]
            Configuration::Sqlite(entry_params, chain_params) => Self::Sqlite(Findex::new(
                EntryTable::setup(SqlEntryBackend::new(&entry_params)?),
                ChainTable::setup(SqlChainBackend::new(&chain_params)?),
            )),

            #[cfg(feature = "redis-interface")]
            Configuration::Redis(entry_params, chain_params) => Self::Redis(Findex::new(
                EntryTable::setup(RedisEntryBackend::connect(&entry_params).await?),
                ChainTable::setup(RedisChainBackend::connect(&chain_params).await?),
            )),

            #[cfg(feature = "rest-interface")]
            Configuration::Rest(token, entry_url, chain_url) => Self::Rest(Findex::new(
                EntryTable::setup(RestEntryBackend::new(RestParameters::new(
                    token.clone(),
                    entry_url,
                ))),
                ChainTable::setup(RestChainBackend::new(RestParameters::new(token, chain_url))),
            )),

            #[cfg(feature = "ffi")]
            Configuration::Ffi(entry_params, chain_params) => Self::Ffi(Findex::new(
                EntryTable::setup(FfiEntryBackend::new(entry_params)),
                ChainTable::setup(FfiChainBackend::new(chain_params)),
            )),

            #[cfg(feature = "python")]
            Configuration::Python(entry_params, chain_params) => Self::Python(Findex::new(
                EntryTable::setup(PythonEntryBackend::new(entry_params)),
                ChainTable::setup(PythonChainBackend::new(chain_params)),
            )),

            #[cfg(feature = "wasm")]
            Configuration::Wasm(entry_params, chain_params) => Self::Wasm(Findex::new(
                EntryTable::setup(WasmEntryBackend::new(entry_params)),
                ChainTable::setup(WasmChainBackend::new(chain_params)),
            )),
        };

        Ok(findex)
    }

    /// Wrapper around Findex [`keygen`](Index::keygen) for static dispatch.
    #[must_use]
    pub fn keygen(&self) -> UserKey {
        match self {
            #[cfg(feature = "sqlite-interface")]
            Self::Sqlite(findex) => findex.keygen(),
            #[cfg(feature = "redis-interface")]
            Self::Redis(findex) => findex.keygen(),
            #[cfg(feature = "ffi")]
            Self::Ffi(findex) => findex.keygen(),
            #[cfg(feature = "python")]
            Self::Python(findex) => findex.keygen(),
            #[cfg(feature = "wasm")]
            Self::Wasm(findex) => findex.keygen(),
            #[cfg(feature = "rest-interface")]
            Self::Rest(findex) => findex.keygen(),
        }
    }

    /// Wrapper around Findex [`search`](Index::search) for static dispatch.
    pub async fn search<
        F: Future<Output = Result<bool, String>>,
        Interrupt: Fn(HashMap<Keyword, HashSet<IndexedValue<Keyword, Data>>>) -> F,
    >(
        &self,
        key: &UserKey,
        label: &Label,
        keywords: Keywords,
        interrupt: &Interrupt,
    ) -> Result<KeywordToDataMap, FindexError<DbInterfaceError>> {
        match self {
            #[cfg(feature = "rest-interface")]
            Self::Rest(findex) => findex.search(key, label, keywords, interrupt).await,
            #[cfg(feature = "ffi")]
            Self::Ffi(findex) => findex.search(key, label, keywords, interrupt).await,
            #[cfg(feature = "python")]
            Self::Python(findex) => findex.search(key, label, keywords, interrupt).await,
            #[cfg(feature = "sqlite-interface")]
            Self::Sqlite(findex) => findex.search(key, label, keywords, interrupt).await,
            #[cfg(feature = "redis-interface")]
            Self::Redis(findex) => findex.search(key, label, keywords, interrupt).await,
            #[cfg(feature = "wasm")]
            Self::Wasm(findex) => findex.search(key, label, keywords, interrupt).await,
        }
    }

    /// Wrapper around Findex [`add`](Index::add) for static dispatch.
    pub async fn add(
        &self,
        key: &UserKey,
        label: &Label,
        additions: IndexedValueToKeywordsMap,
    ) -> Result<Keywords, FindexError<DbInterfaceError>> {
        match self {
            #[cfg(feature = "sqlite-interface")]
            Self::Sqlite(findex) => findex.add(key, label, additions).await,
            #[cfg(feature = "redis-interface")]
            Self::Redis(findex) => findex.add(key, label, additions).await,
            #[cfg(feature = "ffi")]
            Self::Ffi(findex) => findex.add(key, label, additions).await,
            #[cfg(feature = "python")]
            Self::Python(findex) => findex.add(key, label, additions).await,
            #[cfg(feature = "wasm")]
            Self::Wasm(findex) => findex.add(key, label, additions).await,
            #[cfg(feature = "rest-interface")]
            Self::Rest(findex) => findex.add(key, label, additions).await,
        }
    }

    /// Wrapper around Findex [`delete`](Index::delete) for static dispatch.
    pub async fn delete(
        &self,
        key: &UserKey,
        label: &Label,
        deletions: IndexedValueToKeywordsMap,
    ) -> Result<Keywords, FindexError<DbInterfaceError>> {
        match self {
            #[cfg(feature = "sqlite-interface")]
            Self::Sqlite(findex) => findex.delete(key, label, deletions).await,
            #[cfg(feature = "redis-interface")]
            Self::Redis(findex) => findex.delete(key, label, deletions).await,
            #[cfg(feature = "ffi")]
            Self::Ffi(findex) => findex.delete(key, label, deletions).await,
            #[cfg(feature = "python")]
            Self::Python(findex) => findex.delete(key, label, deletions).await,
            #[cfg(feature = "wasm")]
            Self::Wasm(findex) => findex.delete(key, label, deletions).await,
            #[cfg(feature = "rest-interface")]
            Self::Rest(findex) => findex.delete(key, label, deletions).await,
        }
    }

    /// Wrapper around Findex [`compact`](Findex::compact) for static dispatch.
    pub async fn compact<
        F: Future<Output = Result<HashSet<Data>, String>>,
        Filter: Fn(HashSet<Data>) -> F,
    >(
        &self,
        old_key: &UserKey,
        new_key: &UserKey,
        old_label: &Label,
        new_label: &Label,
        compacting_rate: f64,
        data_filter: &Filter,
    ) -> Result<(), FindexError<DbInterfaceError>> {
        match self {
            #[cfg(feature = "sqlite-interface")]
            Self::Sqlite(findex) => {
                findex
                    .compact(
                        old_key,
                        new_key,
                        old_label,
                        new_label,
                        compacting_rate,
                        data_filter,
                    )
                    .await
            }
            #[cfg(feature = "redis-interface")]
            Self::Redis(findex) => {
                findex
                    .compact(
                        old_key,
                        new_key,
                        old_label,
                        new_label,
                        compacting_rate,
                        data_filter,
                    )
                    .await
            }
            #[cfg(feature = "ffi")]
            Self::Ffi(findex) => {
                findex
                    .compact(
                        old_key,
                        new_key,
                        old_label,
                        new_label,
                        compacting_rate,
                        data_filter,
                    )
                    .await
            }
            #[cfg(feature = "python")]
            Self::Python(findex) => {
                findex
                    .compact(
                        old_key,
                        new_key,
                        old_label,
                        new_label,
                        compacting_rate,
                        data_filter,
                    )
                    .await
            }
            #[cfg(feature = "wasm")]
            Self::Wasm(findex) => {
                findex
                    .compact(
                        old_key,
                        new_key,
                        old_label,
                        new_label,
                        compacting_rate,
                        data_filter,
                    )
                    .await
            }
            #[cfg(feature = "rest-interface")]
            Self::Rest(findex) => {
                findex
                    .compact(
                        old_key,
                        new_key,
                        old_label,
                        new_label,
                        compacting_rate,
                        data_filter,
                    )
                    .await
            }
        }
    }
}
