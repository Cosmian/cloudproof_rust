//! This module defines the tests that are to be passed by each backend.

// Used to avoid inserting `#[cfg(...)]` everywhere.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use base64::{engine::general_purpose, Engine};
use cosmian_crypto_core::{CsRng, FixedSizeCBytes, RandomFixedSizeCBytes};
use cosmian_findex::{
    Data, IndexedValue, IndexedValueToKeywordsMap, Keyword, Keywords, Label, UserKey,
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

use super::DbInterfaceError;
use crate::{Configuration, InstantiatedFindex};

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

fn get_users() -> Result<Vec<User>, DbInterfaceError> {
    let dataset = std::fs::read_to_string("datasets/users.json")?;
    serde_json::from_str::<Vec<User>>(&dataset)
        .map_err(|e| DbInterfaceError::Serialization(e.to_string()))
}

/// Generate the key used in the tests. In case the test is a non-regression, the key from
/// `dataset` is used. Otherwise a new random key is generated.
fn get_key(is_non_regression: bool) -> UserKey {
    if is_non_regression {
        let bytes = general_purpose::STANDARD
            .decode(std::fs::read_to_string("datasets/key.txt").unwrap())
            .map_err(|e| DbInterfaceError::Other(e.to_string()))
            .unwrap();
        UserKey::try_from_slice(bytes.as_slice()).unwrap()
    } else {
        let mut rng = CsRng::from_entropy();
        UserKey::new(&mut rng)
    }
}

fn get_label(is_non_regression: bool) -> Label {
    if is_non_regression {
        Label::from(
            std::fs::read_to_string("datasets/label.txt")
                .unwrap()
                .as_str(),
        )
    } else {
        let mut rng = CsRng::from_entropy();
        Label::random(&mut rng)
    }
}

/// Indexes each user for each one of its fields.
async fn insert_users(findex: &InstantiatedFindex, key: &UserKey, label: &Label) {
    // 1. Index the position of each user by each one of its values.
    let users = get_users().unwrap();
    let additions = users
        .iter()
        .enumerate()
        .map(|(idx, user)| {
            (
                IndexedValue::Data(Data::from((idx as i64).to_be_bytes().as_slice())),
                user.values()
                    .iter()
                    .map(|word| Keyword::from(word.as_bytes()))
                    .collect::<HashSet<_>>(),
            )
        })
        .collect::<Vec<(IndexedValue<Keyword, Data>, HashSet<Keyword>)>>();

    trace!("Upsert indexes.");

    const MAX_BATCH_SIZE: usize = 10;
    let n_batches = additions.len() / MAX_BATCH_SIZE;

    for i in 0..n_batches {
        let additions: HashMap<IndexedValue<Keyword, Data>, HashSet<Keyword>> = additions
            [i * MAX_BATCH_SIZE..(i + 1) * MAX_BATCH_SIZE]
            .iter()
            .cloned()
            .collect();
        findex
            .add(key, label, IndexedValueToKeywordsMap::from(additions))
            .await
            .unwrap();
    }
    let additions: HashMap<IndexedValue<Keyword, Data>, HashSet<Keyword>> = additions
        [n_batches * MAX_BATCH_SIZE..]
        .iter()
        .cloned()
        .collect();
    findex
        .add(key, label, IndexedValueToKeywordsMap::from(additions))
        .await
        .unwrap();
}

/// Asserts each user can be retrieved using each field it is indexed for.
async fn find_users(findex: &InstantiatedFindex, key: &UserKey, label: &Label) {
    let users = get_users().unwrap();

    // Assert results are reachable from each indexing keyword.
    for (idx, user) in users.iter().enumerate() {
        trace!("Search indexes.");

        let res = findex
            .search(
                key,
                label,
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
            let location = Data::from((idx as i64).to_be_bytes().as_slice());
            assert!(res.contains_key(&keyword));
            let word_res = res.get(&keyword).unwrap();
            assert!(word_res.contains(&location));
        }
    }
}

/// This test:
/// 1. Indexed each user using each one of its fields; upserts are done in
///    several batches in order not to create a compact index.
/// 2. Asserts that searching each for field of each user allows retrieving the
///    corresponding user index.
/// 3. Asserts that compact operations can be run on the backend.
/// 4. Asserts that the correctness of the search as defined in step 2.
///
/// The `.db` file produced by this test should be okay to use in the non-regression test.
pub async fn test_backend(config: Configuration) {
    let is_non_regression = false;

    let findex = InstantiatedFindex::new(config).await.unwrap();
    let key = get_key(is_non_regression);
    let label = get_label(is_non_regression);

    insert_users(&findex, &key, &label).await;

    find_users(&findex, &key, &label).await;

    let mut rng = CsRng::from_entropy();
    let new_key = UserKey::new(&mut rng);
    let new_label = Label::random(&mut rng);

    println!("Compact indexes.");
    findex
        .compact(
            &key,
            &new_key,
            &label,
            &new_label,
            1f64,
            &|indexed_data| async { Ok(indexed_data) },
        )
        .await
        .unwrap();

    println!("Search indexes.");

    find_users(&findex, &new_key, &new_label).await;
}

pub async fn test_non_regression(config: Configuration) {
    let is_non_regression = true;
    let key = get_key(is_non_regression);
    let label = get_label(is_non_regression);

    let mut expected_results: Vec<i64> =
        serde_json::from_str(include_str!("../../datasets/expected_db_uids.json"))
            .map_err(|e| DbInterfaceError::Serialization(e.to_string()))
            .unwrap();
    expected_results.sort_unstable();

    let findex = InstantiatedFindex::new(config).await.unwrap();

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

pub async fn test_generate_non_regression_db(config: Configuration) {
    let is_non_regression = true;

    let findex = InstantiatedFindex::new(config).await.unwrap();
    let key = get_key(is_non_regression);
    let label = get_label(is_non_regression);

    insert_users(&findex, &key, &label).await;
    find_users(&findex, &key, &label).await;
}
