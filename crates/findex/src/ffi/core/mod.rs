//! Implements Findex traits for [`FindexUser`] and declare FFI types for the
//! callbacks.

#[macro_use]
pub(crate) mod utils;
mod callbacks;
mod traits;

pub use self::callbacks::*;

/// Implements Findex traits.
#[derive(Debug)]
pub struct FindexUser {
    pub(crate) entry_table_number: usize,
    pub(crate) progress: Option<ProgressCallback>,
    pub(crate) fetch_all_entry_table_uids: Option<FetchAllEntryTableUidsCallback>,
    pub(crate) fetch_entry: Option<FetchEntryTableCallback>,
    pub(crate) fetch_chain: Option<FetchChainTableCallback>,
    pub(crate) upsert_entry: Option<UpsertEntryTableCallback>,
    pub(crate) insert_chain: Option<InsertChainTableCallback>,
    pub(crate) update_lines: Option<UpdateLinesCallback>,
    pub(crate) list_removed_locations: Option<ListRemovedLocationsCallback>,
}
