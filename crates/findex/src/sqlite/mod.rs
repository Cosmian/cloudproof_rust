//! This module implements the Findex interface for `SQlite`. It has been
//! written for testing purpose only.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    usize,
};

use cosmian_findex::{
    core::{FindexSearch, FindexUpsert, IndexedValue, KeyingMaterial, Keyword, Label, Location},
    error::FindexErr,
};
use rusqlite::Connection;

use crate::{
    error::Error,
    generic_parameters::MASTER_KEY_LENGTH,
    sqlite::{database::SqliteDatabase, findex::RusqliteFindex},
};

mod database;
mod findex;
#[cfg(test)]
mod tests;
mod utils;

pub use utils::delete_db;

use super::generic_parameters::SECURE_FETCH_CHAINS_BATCH_SIZE;

pub async fn upsert(sqlite_db_path: &PathBuf, dataset_path: &str) -> Result<(), Error> {
    //
    // Prepare database
    //
    let mut connection = Connection::open(sqlite_db_path)?;
    SqliteDatabase::new(&connection, dataset_path)?;

    //
    // Prepare data to index: we want to index all the user metadata found in
    // database. For each user, we create an unique database UID which will be
    // securely indexed with Findex.
    //
    let users = SqliteDatabase::select_all_users(&connection)?;
    let mut locations_and_words = HashMap::new();
    for (idx, user) in users.iter().enumerate() {
        let mut words = HashSet::new();
        for word in &user.values() {
            words.insert(Keyword::from(word.as_bytes()));
        }
        locations_and_words.insert(
            IndexedValue::Location(Location::from((idx as i64).to_be_bytes().as_slice())),
            words,
        );
    }

    //
    // Create upsert instance
    //
    let mut rusqlite_upsert = RusqliteFindex {
        connection: &mut connection,
    };
    let label = Label::from(include_bytes!("../../../../tests/findex/datasets/label").to_vec());
    let master_key_str = include_str!("../../../../tests/findex/datasets/key.json");
    let master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::try_from(master_key_str)?;

    rusqlite_upsert
        .upsert(locations_and_words, &master_key, &label)
        .await?;

    connection
        .close()
        .map_err(|e| Error::Sqlite(format!("Error while closing connection: {e:?}")))
}

pub async fn search(
    sqlite_path: &PathBuf,
    bulk_words: HashSet<Keyword>,
    check: bool,
) -> Result<(), Error> {
    let mut connection = Connection::open(sqlite_path)?;
    let mut rusqlite_search = RusqliteFindex {
        connection: &mut connection,
    };
    let master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::try_from(include_str!(
        "../../../../tests/findex/datasets/key.json"
    ))?;

    let label = Label::from(include_bytes!("../../../../tests/findex/datasets/label").to_vec());
    let results = rusqlite_search
        .search(
            &bulk_words,
            &master_key,
            &label,
            10000,
            usize::MAX,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    let mut db_uids = Vec::with_capacity(results.len());
    for (_, locations) in results {
        for location in locations {
            let db_uid = i64::from_be_bytes(
                (*location)
                    .try_into()
                    .map_err(|e| FindexErr::ConversionError(format!("Invalid location: {e}")))?,
            );
            db_uids.push(db_uid);
        }
    }
    if check {
        db_uids.sort_unstable();
        let mut search_results: Vec<i64> = serde_json::from_str(include_str!(
            "../../../../tests/findex/datasets/expected_db_uids.json"
        ))?;
        search_results.sort_unstable();
        assert_eq!(db_uids, search_results);
    }
    Ok(())
}
