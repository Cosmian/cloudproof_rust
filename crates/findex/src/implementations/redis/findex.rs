use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use cosmian_findex::{
    parameters::{
        BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KMAC_KEY_LENGTH, KWI_LENGTH, MASTER_KEY_LENGTH, UID_LENGTH,
    },
    EncryptedMultiTable, EncryptedTable, FetchChains, FindexCallbacks, FindexCompact, FindexSearch,
    FindexUpsert, IndexedValue, KeyingMaterial, Keyword, Label, Location, Uid, Uids, UpsertData,
};
use redis::{aio::ConnectionManager, pipe, AsyncCommands, Script};
use tokio::sync::RwLock;
use tracing::trace;

use super::{error::FindexRedisError, RemovedLocationsFinder};

/// The length of the prefix of the table name in bytes
/// 0x00ee for the entry table
/// 0x00ef for the chain table
const TABLE_PREFIX_LENGTH: usize = 2;

#[derive(Copy, Clone)]
enum FindexTable {
    Entry = 0xee,
    Chain = 0xef,
}

/// Generate a key for the entry table or chain table
fn key(table: FindexTable, uid: &[u8]) -> Vec<u8> {
    [&[0x00, table as u8], uid].concat()
}

pub struct FindexRedis {
    // we keep redis_url for the updateLines method
    manager: ConnectionManager,
    upsert_script: Script,
    removed_locations_finder: Arc<dyn RemovedLocationsFinder + Sync + Send>,
    compact_lock: RwLock<()>,
}

impl FindexRedis {
    /// The conditional upsert script used to
    /// only update a table if the previous value matches ARGV[2].
    /// When the value does not match, the previous value is returned
    const CONDITIONAL_UPSERT_SCRIPT: &'static str = r"
        local value=redis.call('GET',ARGV[1])
        if((value==false) or (not(value == false) and (ARGV[2] == value))) then
            redis.call('SET', ARGV[1], ARGV[3])
            return
        else
            return value
        end;
    ";

    /// Connect to a Redis server
    ///
    /// # Arguments
    ///  * `redis_url` - The Redis URL e.g.
    ///    "redis://user:password@localhost:6379"
    pub async fn connect(
        redis_url: &str,
        removed_locations_finder: Arc<dyn RemovedLocationsFinder + Sync + Send>,
    ) -> Result<Self, FindexRedisError> {
        let client = redis::Client::open(redis_url)?;
        let manager = ConnectionManager::new(client).await?;

        Ok(FindexRedis {
            manager,
            upsert_script: Script::new(Self::CONDITIONAL_UPSERT_SCRIPT),
            removed_locations_finder,
            compact_lock: RwLock::new(()),
        })
    }

    /// Connect to a Redis server with a `ConnectionManager`
    pub async fn connect_with_manager(
        manager: ConnectionManager,
        removed_locations_finder: Arc<dyn RemovedLocationsFinder + Sync + Send>,
    ) -> Result<Self, FindexRedisError> {
        Ok(FindexRedis {
            manager,
            upsert_script: Script::new(Self::CONDITIONAL_UPSERT_SCRIPT),
            removed_locations_finder,
            compact_lock: RwLock::new(()),
        })
    }

    /// Clear all indexes
    ///
    /// # Warning
    /// This is definitive
    pub async fn clear_indexes(&self) -> Result<(), FindexRedisError> {
        redis::cmd("FLUSHDB")
            .query_async(&mut self.manager.clone())
            .await?;
        Ok(())
    }

    /// Upsert the given chain elements in Findex tables.
    ///
    /// # Parameters
    ///
    /// - `master_key`  : Findex master key
    /// - `label`       : additional public information used in key hashing
    /// - `additions`   : values to indexed for a set of keywords
    /// - `deletions`   : values to remove from the indexes for a set of
    ///   keywords
    ///
    /// # Returns
    /// The set of new keywords that were added
    pub async fn upsert(
        &self,
        master_key: &[u8; MASTER_KEY_LENGTH],
        label: &[u8],
        additions: HashMap<IndexedValue, HashSet<Keyword>>,
        deletions: HashMap<IndexedValue, HashSet<Keyword>>,
    ) -> Result<HashSet<Keyword>, FindexRedisError> {
        FindexUpsert::upsert(
            self,
            &KeyingMaterial::<MASTER_KEY_LENGTH>::from(*master_key),
            &Label::from(label),
            additions,
            deletions,
        )
        .await
        .map_err(FindexRedisError::from)
    }

    /// Searches for the `Location`s indexed by the given `Keyword`s. This is
    /// the entry point of the Findex search.
    ///
    /// # Parameters
    ///
    /// - `master_key`          : Findex master key
    /// - `label`               : public label
    /// - `keywords`            : keywords to search
    pub async fn search(
        &self,
        master_key: &[u8; MASTER_KEY_LENGTH],
        label: &[u8],
        keywords: HashSet<Keyword>,
    ) -> Result<HashMap<Keyword, HashSet<Location>>, FindexRedisError> {
        let res = FindexSearch::search(
            self,
            &KeyingMaterial::<MASTER_KEY_LENGTH>::from(*master_key),
            &Label::from(label),
            keywords,
        )
        .await?;
        Ok(res)
    }

    /// Replaces all the Index Entry Table UIDs and values. New UIDs are derived
    /// using the given label and the KMAC key derived from the new master key.
    /// The values are decrypted using the DEM key derived from the master key
    /// and re-encrypted using the DEM key derived from the new master key.
    ///
    /// Randomly selects index entries and recompact their associated chains.
    /// Chains indexing no existing location are removed. Others are recomputed
    /// from a new keying material. This removes unneeded paddings. New UIDs are
    /// derived for the chain and values are re-encrypted using a DEM key
    /// derived from the new keying material.
    ///
    /// - `master_key`                      : master key used to generate the
    ///   current index
    /// - `new_master_key`                  : master key used to generate the
    ///   new index
    /// - `label`                           : label used to generate the new
    ///   index
    /// - `num_reindexing_before_full_set`  : average number of calls to compact
    ///   needed to recompute all of the Chain Table.
    ///
    /// **WARNING**: the compact operation *cannot* be done concurrently with
    /// upsert operations. This could result in corrupted indexes.
    pub async fn compact(
        &self,
        master_key: &[u8; 16],
        new_master_key: &[u8; 16],
        label: &[u8],
        num_reindexing_before_full_set: u32,
    ) -> Result<(), FindexRedisError> {
        FindexCompact::compact(
            self,
            &KeyingMaterial::<MASTER_KEY_LENGTH>::from(*master_key),
            &KeyingMaterial::<MASTER_KEY_LENGTH>::from(*new_master_key),
            &Label::from(label),
            num_reindexing_before_full_set,
        )
        .await?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl FindexCallbacks<FindexRedisError, UID_LENGTH> for FindexRedis {
    async fn progress(
        &self,
        _results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, FindexRedisError> {
        //TODO: allow passing callback fn on connect
        Ok(true)
    }

    async fn fetch_all_entry_table_uids(&self) -> Result<Uids<UID_LENGTH>, FindexRedisError> {
        let keys: Vec<Vec<u8>> = self
            .manager
            .clone()
            .keys(key(FindexTable::Entry, b"*"))
            .await?;
        trace!("fetch_all_entry_table_uids num keywords: {}", keys.len());
        Ok(Uids(
            keys.iter()
                .map(|v| {
                    let mut uid = [0u8; UID_LENGTH];
                    uid.copy_from_slice(&v[TABLE_PREFIX_LENGTH..]);
                    Uid::from(uid)
                })
                .collect(),
        ))
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedMultiTable<UID_LENGTH>, FindexRedisError> {
        trace!(
            "fetch_entry_table num keywords: {}:",
            entry_table_uids.0.len(),
        );
        // guard against empty uids
        if entry_table_uids.0.is_empty() {
            return Ok(EncryptedMultiTable::default());
        }

        // collect uids from the entry table
        let uids: Vec<Uid<32>> = entry_table_uids.0.into_iter().collect();

        // build Redis keys
        let keys: Vec<Vec<u8>> = uids
            .iter()
            .map(|uid| key(FindexTable::Entry, uid))
            .collect();

        // mget the values from the Redis keys
        let values: Vec<Vec<u8>> = self.manager.clone().mget(keys).await?;

        // discard empty values
        let tuples = uids
            .into_iter()
            .zip(values)
            .filter(|(_uid, v)| !v.is_empty())
            .collect::<Vec<_>>();
        trace!("fetch_entry_table non empty tuples len: {}", tuples.len(),);

        Ok(EncryptedMultiTable(tuples))
    }

    async fn fetch_chain_table(
        &self,
        chain_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexRedisError> {
        trace!(
            "fetch_chain_table num entries: {}:",
            chain_table_uids.0.len(),
        );

        //guard against empty uids
        if chain_table_uids.0.is_empty() {
            return Ok(EncryptedTable::default());
        }

        // collect uids from the chain table
        let uids: Vec<Uid<32>> = chain_table_uids.0.into_iter().collect();

        let keys: Vec<Vec<u8>> = uids
            .iter()
            .map(|uid| key(FindexTable::Chain, uid))
            .collect();
        let values: Vec<Vec<u8>> = self.manager.clone().mget(keys).await?;

        Ok(EncryptedTable::from(
            uids.into_iter()
                .zip(values)
                .filter(|(_uid, v)| !v.is_empty())
                .collect::<HashMap<Uid<UID_LENGTH>, Vec<u8>>>(),
        ))
    }

    async fn upsert_entry_table(
        &self,
        modifications: UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexRedisError> {
        // Prevent upserting while compacting
        if self.compact_lock.try_read().is_err() {
            return Err(FindexRedisError::Compacting);
        }

        trace!("upsert_entry_table num keywords {:?}", modifications.len());

        let mut rejected = EncryptedTable::default();
        for (uid, (old_value, new_value)) in modifications {
            let value: Vec<u8> = self
                .upsert_script
                .arg(key(FindexTable::Entry, &uid))
                .arg(old_value.unwrap_or_default())
                .arg(new_value)
                .invoke_async(&mut self.manager.clone())
                .await?;
            if !value.is_empty() {
                rejected.insert(uid, value);
            }
        }
        trace!("upsert_entry_table rejected: {}", rejected.len());
        Ok(rejected)
    }

    async fn insert_chain_table(
        &self,
        items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexRedisError> {
        let mut pipe = pipe();
        for item in items {
            pipe.set(key(FindexTable::Chain, &item.0), item.1);
        }
        pipe.atomic().query_async(&mut self.manager.clone()).await?;
        Ok(())
    }

    async fn update_lines(
        &self,
        chain_table_uids_to_remove: Uids<UID_LENGTH>,
        new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexRedisError> {
        // Prevent compacting while already compacting
        // We could add support to make sure we are not upserting
        let _compact_lock = match self.compact_lock.try_write() {
            Ok(lock) => lock,
            Err(_) => return Err(FindexRedisError::Compacting), /* another thread is compacting already so we return an error */
        };

        trace!(
            "update_lines chain_table_uids_to_remove: {}, new_encrypted_entry_table_items: {}, \
             new_encrypted_chain_table_items: {}",
            chain_table_uids_to_remove.len(),
            new_encrypted_entry_table_items.len(),
            new_encrypted_chain_table_items.len()
        );

        // Collect all the entry table keys to delete.
        let old_entries: Vec<Vec<u8>> = self
            .manager
            .clone()
            .keys(key(FindexTable::Entry, b"*"))
            .await?;
        let mut old_entries = old_entries.into_iter().collect::<HashSet<_>>();

        // Add new chains.
        let mut pipeline = pipe();
        for item in new_encrypted_chain_table_items {
            pipeline.set(key(FindexTable::Chain, &item.0), item.1);
        }
        pipeline
            .atomic()
            .query_async(&mut self.manager.clone())
            .await?;

        // Add new entries.
        // keep track of the keys we added so we don't delete them later on
        let mut pipeline = pipe();
        for item in new_encrypted_entry_table_items {
            let key = key(FindexTable::Entry, &item.0);
            // Do not delete that key later on.
            old_entries.remove(&key);
            pipeline.set(key, item.1);
        }
        pipeline
            .atomic()
            .query_async(&mut self.manager.clone())
            .await?;

        // Delete old entries.
        let mut pipeline = pipe();
        for entry_key in old_entries {
            pipeline.del(entry_key);
        }
        pipeline
            .atomic()
            .query_async(&mut self.manager.clone())
            .await?;

        // Delete the old chains.
        let mut pipeline = pipe();
        for item in chain_table_uids_to_remove {
            pipeline.del(key(FindexTable::Chain, &item));
        }
        pipeline
            .atomic()
            .query_async(&mut self.manager.clone())
            .await?;

        Ok(())
    }

    async fn list_removed_locations(
        &self,
        locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexRedisError> {
        self.removed_locations_finder
            .find_removed_locations(locations)
            .await
    }
}

impl FetchChains<UID_LENGTH, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KWI_LENGTH, FindexRedisError>
    for FindexRedis
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
        FindexRedisError,
    > for FindexRedis
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
        FindexRedisError,
    > for FindexRedis
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
        FindexRedisError,
    > for FindexRedis
{
}
