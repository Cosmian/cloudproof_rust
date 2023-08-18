//! This module defines the tests that are to be passed by each backend.

#![cfg(test)]
// Used to avoid inserting `#[cfg(...)]` everywhere.
#![allow(dead_code)]

use std::collections::HashSet;

use base64::{engine::general_purpose, Engine};
use cosmian_crypto_core::{CsRng, FixedSizeCBytes, RandomFixedSizeCBytes};
use cosmian_findex::{
    ChainTable, DxEnc, EdxStore, EntryTable, Findex, Index, IndexedValue, Keyword, Keywords, Label,
    Location, UserKey, ENTRY_LENGTH, LINK_LENGTH,
};
use faker_rand::{
    en_us::addresses::PostalCode,
    fr_fr::{
        addresses::Division,
        internet::Email,
        names::{FirstName, LastName},
        phones::PhoneNumber,
    },
};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use tracing::trace;

use super::BackendError;
use crate::{BackendConfiguration, InstantiatedFindex};

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    pub(crate) firstName: String,
    pub(crate) lastName: String,
    pub(crate) phone: String,
    pub(crate) email: String,
    pub(crate) country: String,
    pub(crate) region: String,
    pub(crate) employeeNumber: String,
    pub(crate) security: String,
}

impl User {
    #[must_use]
    pub fn new() -> Self {
        Self {
            firstName: rand::random::<FirstName>().to_string(),
            lastName: rand::random::<LastName>().to_string(),
            phone: rand::random::<PhoneNumber>().to_string(),
            email: rand::random::<Email>().to_string(),
            country: "France".to_string(),
            region: rand::random::<Division>().to_string(),
            employeeNumber: rand::random::<PostalCode>().to_string(),
            security: "confidential".to_string(),
        }
    }

    #[must_use]
    pub fn values(&self) -> Vec<String> {
        vec![
            self.firstName.clone(),
            self.lastName.clone(),
            self.phone.clone(),
            self.email.clone(),
            self.country.clone(),
            self.region.clone(),
            self.employeeNumber.clone(),
            self.security.clone(),
        ]
    }
}

impl Default for User {
    fn default() -> Self {
        Self::new()
    }
}

fn get_users() -> Result<Vec<User>, BackendError> {
    let dataset = std::fs::read_to_string("datasets/users.json")?;
    serde_json::from_str::<Vec<User>>(&dataset)
        .map_err(|e| BackendError::Serialization(e.to_string()))
}

/// This test:
/// 1. Indexed each user using each one of its fields; upserts are done in
///    several batches in order not to create a compact index.
/// 2. Asserts that searching each for field of each user allows retrieving the
///    corresponding user index.
/// 3. Asserts that compact operations can be run on the backend.
/// 4. Asserts that the correctness of the search as defined in step 2.
pub async fn test_backend(config: BackendConfiguration) {
    // 1. Index the position of each user by each one of its values.
    let users = get_users().unwrap();
    let additions = users
        .iter()
        .enumerate()
        .map(|(idx, user)| {
            (
                IndexedValue::Data(Location::from((idx as i64).to_be_bytes().as_slice())),
                user.values()
                    .iter()
                    .map(|word| Keyword::from(word.as_bytes()))
                    .collect::<HashSet<_>>(),
            )
        })
        .collect::<Vec<(IndexedValue<Keyword, Location>, HashSet<Keyword>)>>();

    let findex = InstantiatedFindex::new(config).await.unwrap();
    let mut rng = CsRng::from_entropy();
    let msk = UserKey::new(&mut rng);
    let label = Label::random(&mut rng);

    trace!("Upsert indexes.");

    const MAX_BATCH_SIZE: usize = 10;
    let n_batches = additions.len() / MAX_BATCH_SIZE;
    for i in 0..n_batches {
        findex
            .add(
                &msk,
                &label,
                additions[i * MAX_BATCH_SIZE..(i + 1) * MAX_BATCH_SIZE]
                    .iter()
                    .cloned()
                    .collect(),
            )
            .await
            .unwrap();
    }
    findex
        .add(
            &msk,
            &label,
            additions[n_batches * MAX_BATCH_SIZE..]
                .iter()
                .cloned()
                .collect(),
        )
        .await
        .unwrap();

    trace!("Search indexes.");

    // Assert results are reachable from each indexing keyword.
    for (idx, user) in users.iter().enumerate() {
        let res = findex
            .search(
                &msk,
                &label,
                Keywords::from_iter(
                    user.values()
                        .into_iter()
                        .map(|word| Keyword::from(word.as_bytes())),
                ),
                &|_| async move { Ok(false) },
            )
            .await
            .unwrap();

        for word in user.values() {
            let keyword = Keyword::from(word.as_bytes());
            let location = Location::from((idx as i64).to_be_bytes().as_slice());
            assert!(res.contains_key(&keyword));
            let word_res = res.get(&keyword).unwrap();
            assert!(word_res.contains(&location));
        }
    }

    println!("Compact indexes.");

    let new_msk = UserKey::new(&mut rng);
    let new_label = Label::random(&mut rng);
    findex
        .compact(
            &msk,
            &new_msk,
            &label,
            &new_label,
            1,
            &|indexed_data| async { Ok(indexed_data) },
        )
        .await
        .unwrap();

    println!("Search indexes.");

    // Assert results are reachable from each indexing keyword.
    for (idx, user) in users.iter().enumerate() {
        let res = findex
            .search(
                &new_msk,
                &new_label,
                Keywords::from_iter(
                    user.values()
                        .into_iter()
                        .map(|word| Keyword::from(word.as_bytes())),
                ),
                &|_| async move { Ok(false) },
            )
            .await
            .unwrap();

        for word in user.values() {
            let keyword = Keyword::from(word.as_bytes());
            let location = Location::from((idx as i64).to_be_bytes().as_slice());
            assert!(res.contains_key(&keyword));
            let word_res = res.get(&keyword).unwrap();
            assert!(word_res.contains(&location));
        }
    }
}

pub async fn test_non_regression<
    Etb: EdxStore<ENTRY_LENGTH, Error = BackendError>,
    Ctb: EdxStore<LINK_LENGTH, Error = BackendError>,
>(
    entry_table_backend: Etb,
    chain_table_backend: Ctb,
) {
    let key = general_purpose::STANDARD
        .decode(include_str!("../../datasets/key.txt"))
        .map_err(|e| BackendError::Other(e.to_string()))
        .unwrap();
    let key = UserKey::try_from_slice(&key).unwrap();
    let label = Label::from(include_bytes!("../../datasets/label.txt").to_vec());

    let mut expected_results: Vec<i64> =
        serde_json::from_str(include_str!("../../datasets/expected_db_uids.json"))
            .map_err(|e| BackendError::Serialization(e.to_string()))
            .unwrap();
    expected_results.sort_unstable();

    let findex = Findex::<BackendError, _, _>::new(
        EntryTable::setup(entry_table_backend),
        ChainTable::setup(chain_table_backend),
    );

    let keyword = Keyword::from("France".as_bytes());
    let results = findex
        .search(
            &key,
            &label,
            Keywords::from_iter([keyword.clone()]),
            &|_| async move { Ok(false) },
        )
        .await
        .unwrap();

    let mut results = results
        .get(&keyword)
        .unwrap()
        .iter()
        .map(|location| i64::from_be_bytes(location.as_ref().try_into().unwrap()))
        .collect::<Vec<_>>();
    results.sort_unstable();

    assert_eq!(results, expected_results);
}
