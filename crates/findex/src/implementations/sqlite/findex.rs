use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_findex::{
    parameters::{
        BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KMAC_KEY_LENGTH, KWI_LENGTH, MASTER_KEY_LENGTH, UID_LENGTH,
    },
    EncryptedMultiTable, EncryptedTable, FetchChains, FindexCallbacks, FindexSearch, FindexUpsert,
    IndexedValue, Keyword, Location, Uid, Uids, UpsertData,
};
use rusqlite::{Connection, OptionalExtension, Result};

use super::{
    utils::{prepare_statement, sqlite_fetch_entry_table_items},
    Error,
};
use crate::ser_de::{deserialize_fetch_entry_table_results, serialize_set};
pub struct SqliteFindex {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteFindex {
    pub fn new(connection: Arc<Mutex<Connection>>) -> Self {
        SqliteFindex { connection }
    }
}

#[async_trait(?Send)]
impl FindexCallbacks<Error, UID_LENGTH> for SqliteFindex {
    async fn progress(
        &self,
        _results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, Error> {
        Ok(true)
    }

    async fn fetch_all_entry_table_uids(&self) -> Result<Uids<UID_LENGTH>, Error> {
        Err(Error::Other(
            "`FindexCompact` is not implemented for `RusqliteFindex`".to_string(),
        ))
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedMultiTable<UID_LENGTH>, Error> {
        let cnx = self
            .connection
            .lock()
            .expect("Rusqlite connection lock poisoned");
        let serialized_res =
            sqlite_fetch_entry_table_items(&cnx, &serialize_set(&entry_table_uids.0)?)?;
        Ok(EncryptedMultiTable(
            deserialize_fetch_entry_table_results(&serialized_res).map_err(Error::from)?,
        ))
    }

    async fn fetch_chain_table(
        &self,
        chain_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, Error> {
        let cnx = self
            .connection
            .lock()
            .expect("Rusqlite connection lock poisoned");
        let mut stmt =
            prepare_statement(&cnx, &serialize_set(&chain_table_uids.0)?, "chain_table")?;

        let mut rows = stmt.raw_query();
        let mut chain_table_items = EncryptedTable::default();
        while let Some(row) = rows.next()? {
            let uid: Vec<u8> = row.get(0)?;
            chain_table_items.insert(Uid::deserialize(&uid)?, row.get(1)?);
        }
        Ok(chain_table_items)
    }

    async fn upsert_entry_table(
        &self,
        items: UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, Error> {
        let mut rejected_items = EncryptedTable::default();
        let mut cnx = self
            .connection
            .lock()
            .expect("Rusqlite connection lock poisoned");
        let tx = cnx.transaction()?;
        for (uid, (old_value, new_value)) in items {
            let actual_value = tx
                .query_row(
                    "SELECT value FROM entry_table WHERE uid = ?1",
                    [uid.to_vec()],
                    |row| row.get::<usize, Vec<u8>>(0),
                )
                .optional()?;
            if actual_value.as_ref() == old_value.as_ref() {
                tx.execute(
                    "REPLACE INTO entry_table (uid, value) VALUES (?1, ?2)",
                    [uid.to_vec(), new_value.clone()],
                )?;
            } else {
                rejected_items.insert(
                    uid,
                    actual_value.ok_or_else(|| {
                        Error::Other("Index entries cannot be removed while upserting.".to_string())
                    })?,
                );
            }
        }
        tx.commit()?;
        Ok(rejected_items)
    }

    async fn insert_chain_table(&self, items: EncryptedTable<UID_LENGTH>) -> Result<(), Error> {
        let mut cnx = self
            .connection
            .lock()
            .expect("Rusqlite connection lock poisoned");
        let tx = cnx.transaction()?;
        for (uid, value) in items.iter() {
            tx.execute(
                "INSERT INTO chain_table (uid, value) VALUES (?1, ?2)",
                [uid.to_vec(), value.clone()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    async fn update_lines(
        &self,
        _chain_table_uids_to_remove: Uids<UID_LENGTH>,
        _new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        _new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), Error> {
        // TODO (TBZ): `FindexCompact` is not implemented for `RusqliteFindex`.
        Err(Error::Other(
            "`FindexCompact` is not implemented for `RusqliteFindex`".to_string(),
        ))
    }

    async fn list_removed_locations(
        &self,
        _locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, Error> {
        // TODO (TBZ): `FindexCompact` is not implemented for `RusqliteFindex`.
        Err(Error::Other(
            "`FindexCompact` is not implemented for `RusqliteFindex`".to_string(),
        ))
    }
}

impl FetchChains<UID_LENGTH, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KWI_LENGTH, Error> for SqliteFindex {}

impl
    FindexUpsert<
        UID_LENGTH,
        BLOCK_LENGTH,
        CHAIN_TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        Error,
    > for SqliteFindex
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
        Error,
    > for SqliteFindex
{
}
