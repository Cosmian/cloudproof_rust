use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use base64::{engine::general_purpose, Engine};
use cloudproof_findex::implementations::sqlite::{utils::delete_db, Error, SqliteFindex};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_findex::{
    FindexSearch, FindexUpsert, IndexedValue, KeyingMaterial, Keyword, Label, Location,
};
use database::{SqliteDatabase, User};
use rusqlite::Connection;
mod database;

pub async fn upsert(sqlite_db_path: &PathBuf, dataset_path: &str) -> Result<(), Error> {
    //
    // Prepare database
    //
    let connection = Arc::new(RwLock::new(Connection::open(sqlite_db_path)?));
    let db = SqliteDatabase::new(connection.clone(), dataset_path)?;

    //
    // Prepare data to index: we want to index all the user metadata found in
    // database. For each user, we create an unique database UID which will be
    // securely indexed with Findex.
    //
    let users = db.select_all_users()?;
    let mut additions = HashMap::with_capacity(users.len());
    for (idx, user) in users.iter().enumerate() {
        let values = user.values();
        let mut words = HashSet::with_capacity(values.len());
        for word in &values {
            words.insert(Keyword::from(word.as_bytes()));
        }
        additions.insert(
            IndexedValue::Location(Location::from((idx as i64).to_be_bytes().as_slice())),
            words,
        );
    }

    //
    // Create upsert instance
    //
    let rusqlite_upsert = SqliteFindex::new(connection.clone());
    let label = Label::from(include_bytes!("./datasets/label").to_vec());
    let master_key_bytes = general_purpose::STANDARD
        .decode(include_str!("./datasets/key.json"))
        .map_err(|e| Error::Other(e.to_string()))?;
    let master_key = KeyingMaterial::deserialize(&master_key_bytes)?;

    rusqlite_upsert
        .upsert(&master_key, &label, additions, HashMap::new())
        .await?;
    Ok(())
}

pub async fn search(
    sqlite_path: &PathBuf,
    bulk_words: HashSet<Keyword>,
    check: bool,
) -> Result<(), Error> {
    let connection = Arc::new(RwLock::new(Connection::open(sqlite_path)?));
    let rusqlite_search = SqliteFindex::new(connection.clone());
    let master_key_bytes = general_purpose::STANDARD
        .decode(include_str!("./datasets/key.json"))
        .map_err(|e| Error::Other(e.to_string()))?;
    let master_key = KeyingMaterial::deserialize(&master_key_bytes)?;

    let label = Label::from(include_bytes!("./datasets/label").to_vec());
    let results = rusqlite_search
        .search(&master_key, &label, bulk_words)
        .await?;
    let mut db_uids = Vec::with_capacity(results.len());
    for (_, locations) in results {
        for location in locations {
            let db_uid = i64::from_be_bytes(
                (*location)
                    .try_into()
                    .map_err(|e| Error::Other(format!("Invalid location: {e}")))?,
            );
            db_uids.push(db_uid);
        }
    }
    if check {
        db_uids.sort_unstable();
        let mut search_results: Vec<i64> =
            serde_json::from_str(include_str!("./datasets/expected_db_uids.json"))?;
        search_results.sort_unstable();
        assert_eq!(db_uids, search_results);
    }
    Ok(())
}

fn generate_new_dataset(nb_user: usize, dataset_filename: &str) {
    let mut users = Vec::with_capacity(nb_user);
    for _ in 0..nb_user {
        users.push(User::new());
    }

    // Save the JSON structure into the other file.
    std::fs::write(
        dataset_filename,
        serde_json::to_string_pretty(&users).unwrap(),
    )
    .unwrap();
}

#[actix_rt::test]
async fn test_findex_sqlite_no_regression() -> Result<(), Error> {
    //
    // Prepare database and create Findex structs
    //
    let db = PathBuf::from("tests/datasets/sqlite.db");

    //
    // Search
    //
    search(
        &db,
        HashSet::from_iter([Keyword::from("France".as_bytes())]),
        true,
    )
    .await?;

    // Empty research (just in case)
    search(&db, HashSet::new(), false).await?;

    Ok(())
}

#[actix_rt::test]
async fn test_findex_sqlite_generate() -> Result<(), Error> {
    //
    // Prepare database and create Findex structs
    //
    let file_path = Path::new("../../target/sqlite.db");
    if file_path.exists() {
        std::fs::remove_file(file_path).map_err(Error::IoError)?;
    }
    let db = PathBuf::from(file_path);

    //
    // Create new database
    //
    upsert(&db, "tests/datasets/data.json").await?;

    //
    // Search - simple check
    //
    search(
        &db,
        HashSet::from_iter([Keyword::from("France".as_bytes())]),
        true,
    )
    .await?;

    Ok(())
}

#[actix_rt::test]
async fn test_different_scenarios() -> Result<(), Error> {
    let db = std::env::temp_dir().join("sqlite_tmp.db");
    for _ in 0..5 {
        //
        // Generate a new dataset and index it
        //
        generate_new_dataset(100, "../../target/french_dataset.json");
        upsert(&db, "../../target/french_dataset.json").await?;

        //
        // Search
        //
        search(
            &db,
            HashSet::<Keyword>::from_iter([Keyword::from("France".as_bytes())]),
            false,
        )
        .await?;
    }

    delete_db(&db)?;
    Ok(())
}
