use std::{
    collections::{HashMap, HashSet},
    ffi::{c_uchar, c_uint, CString},
    os::raw::{c_char, c_int},
    sync::{
        atomic::{AtomicI32, Ordering},
        RwLock,
    },
};

use base64::{engine::general_purpose::STANDARD, Engine};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    reexport::rand_core::SeedableRng,
    CsRng,
};
use cosmian_ffi_utils::{
    error::get_last_error, ffi_bail, ffi_read_bytes, ffi_unwrap, ffi_write_bytes,
};
use cosmian_findex::{
    parameters::{MASTER_KEY_LENGTH, UID_LENGTH},
    EncryptedTable, IndexedValue, Keyword, Location, Uid, UpsertData,
};
use lazy_static::lazy_static;
use rand::Rng;

use crate::{
    ffi::{
        api::{h_search, h_upsert},
        core::utils::serialize_indexed_values,
    },
    ser_de::{deserialize_hashmap, deserialize_set, serialize_fetch_entry_table_results},
};

// A static cache of the Encryption Caches
lazy_static! {
    static ref ENCRYPTED_TABLES_CACHE_MAP: RwLock<HashMap<i32, EncryptedTable<UID_LENGTH>>> =
        RwLock::new(HashMap::new());
    static ref ENCRYPTED_CACHE_ID: std::sync::atomic::AtomicI32 = AtomicI32::new(0);
}

fn get_table(id: i32) -> EncryptedTable<UID_LENGTH> {
    let map = ENCRYPTED_TABLES_CACHE_MAP
        .read()
        .expect("a read mutex on the encryption cache failed");
    map.get(&id).unwrap().clone()
}

fn get_entry_table() -> EncryptedTable<UID_LENGTH> {
    get_table(0)
}

fn get_chain_table() -> EncryptedTable<UID_LENGTH> {
    get_table(1)
}

/// Converts the given strings as a `HashSet` of Keywords.
///
/// - `keywords`    : strings to convert
fn hashset_keywords(keywords: &[&'static str]) -> HashSet<Keyword> {
    keywords
        .iter()
        .map(|keyword| Keyword::from(*keyword))
        .collect()
}

struct FindexTest {}

impl FindexTest {
    fn init() {
        let id = ENCRYPTED_CACHE_ID.fetch_add(1, Ordering::Acquire);
        let mut map = ENCRYPTED_TABLES_CACHE_MAP
            .write()
            .expect("A write mutex on encryption cache failed");
        map.insert(id, EncryptedTable::<UID_LENGTH>::default());

        let id = ENCRYPTED_CACHE_ID.fetch_add(1, Ordering::Acquire);
        map.insert(id, EncryptedTable::<UID_LENGTH>::default());
    }

    extern "C" fn progress(_uids_ptr: *const c_uchar, _uids_len: c_uint) -> c_int {
        1
    }

    extern "C" fn fetch_entry(
        entries_ptr: *mut c_uchar,
        entries_len: *mut c_uint,
        uids_ptr: *const c_uchar,
        uids_len: c_uint,
    ) -> c_int {
        let entry_table_uids = unsafe {
            let uids_bytes: &[u8] = ffi_read_bytes!("uid", uids_ptr, uids_len);
            ffi_unwrap!(deserialize_set(uids_bytes), "deserialize uids")
        };

        // Get Map from cache
        let map = ENCRYPTED_TABLES_CACHE_MAP
            .read()
            .expect("a read mutex on the encryption cache failed");
        let entry_table = if let Some(cache) = map.get(&0) {
            cache
        } else {
            ffi_bail!(format!("FindexTest: no cache for handle: 0"));
        };

        let fetch_entry_results: Vec<(Uid<UID_LENGTH>, Vec<u8>)> = entry_table_uids
            .into_iter()
            .filter_map(|uid| entry_table.get(&uid).cloned().map(|value| (uid, value)))
            .collect();

        let serialized_fetch_entry_results = ffi_unwrap!(
            serialize_fetch_entry_table_results(fetch_entry_results),
            "serialize fetch entry results"
        );

        let results_len = &mut (serialized_fetch_entry_results.len() as c_int);
        unsafe {
            ffi_write_bytes!(
                "entries",
                &serialized_fetch_entry_results,
                entries_ptr,
                results_len
            );
            *entries_len = serialized_fetch_entry_results.len() as u32;
        }

        0
    }

    extern "C" fn fetch_chain(
        chains_ptr: *mut c_uchar,
        chains_len: *mut c_uint,
        uids_ptr: *const c_uchar,
        uids_len: c_uint,
    ) -> c_int {
        let chain_table_uids = unsafe {
            let uids_bytes: &[u8] = ffi_read_bytes!("uid", uids_ptr, uids_len);
            ffi_unwrap!(deserialize_set(uids_bytes), "deserialize uids")
        };

        // Get Map from cache
        let map = ENCRYPTED_TABLES_CACHE_MAP
            .read()
            .expect("a read mutex on the encryption cache failed");
        let chain_table = if let Some(cache) = map.get(&1) {
            cache
        } else {
            ffi_bail!(format!("FindexTest: no cache for handle: 1"));
        };

        let fetch_chain_results: Vec<(Uid<UID_LENGTH>, Vec<u8>)> = chain_table_uids
            .into_iter()
            .filter_map(|uid| chain_table.get(&uid).cloned().map(|value| (uid, value)))
            .collect();

        let serialized_fetch_chain_results = ffi_unwrap!(
            serialize_fetch_entry_table_results(fetch_chain_results),
            "serialize fetch chain results"
        );

        let results_len = &mut (serialized_fetch_chain_results.len() as c_int);
        unsafe {
            ffi_write_bytes!(
                "chains",
                &serialized_fetch_chain_results,
                chains_ptr,
                results_len
            );
            *chains_len = serialized_fetch_chain_results.len() as u32;
        }

        0
    }

    extern "C" fn upsert_entry(
        outputs_ptr: *mut c_uchar,
        outputs_len: *mut c_uint,
        entries_ptr: *const c_uchar,
        entries_len: c_uint,
    ) -> c_int {
        let modifications = unsafe {
            let entries_bytes: &[u8] = ffi_read_bytes!("entries", entries_ptr, entries_len);
            let mut de = Deserializer::new(entries_bytes);
            let modifications: UpsertData<UID_LENGTH> =
                ffi_unwrap!(de.read(), "deserialize UpsertData");
            modifications
        };

        // Get Map from cache
        let mut map = ENCRYPTED_TABLES_CACHE_MAP
            .write()
            .expect("a read mutex on the encryption cache failed");
        let entry_table = if let Some(cache) = map.get_mut(&0) {
            cache
        } else {
            ffi_bail!(format!("FindexTest: no cache for handle: 0"));
        };

        let mut rejected = EncryptedTable::default();
        // Simulate insertion failures.
        let mut rng = CsRng::from_entropy();
        for (uid, (old_value, new_value)) in modifications {
            // Reject insert with probability 0.2.
            if entry_table.contains_key(&uid) && rng.gen_range(0..5) == 0 {
                rejected.insert(uid, old_value.unwrap_or_default());
            } else {
                entry_table.insert(uid, new_value);
            }
        }

        // Serialize rejected entries
        let mut se = Serializer::new();
        let serialized_rejected_size =
            ffi_unwrap!(rejected.write(&mut se), "serialize rejected entries");
        let serialized_rejected = se.finalize();

        let results_len = &mut (serialized_rejected_size as c_int);
        unsafe {
            ffi_write_bytes!(
                "rejected_entries",
                &serialized_rejected,
                outputs_ptr,
                results_len
            );
            *outputs_len = serialized_rejected.len() as u32;
        }

        0
    }

    extern "C" fn insert_chain(chains_ptr: *const c_uchar, chains_len: c_uint) -> c_int {
        let chains = unsafe {
            let chains_bytes: &[u8] = ffi_read_bytes!("chains", chains_ptr, chains_len);
            let mut de = Deserializer::new(chains_bytes);
            let chains: EncryptedTable<UID_LENGTH> =
                ffi_unwrap!(de.read(), "deserialize UpsertData");
            chains
        };

        // Get Map from cache
        let mut map = ENCRYPTED_TABLES_CACHE_MAP
            .write()
            .expect("a read mutex on the encryption cache failed");
        let chain_table = if let Some(cache) = map.get_mut(&1) {
            cache
        } else {
            ffi_bail!(format!("FindexTest: no cache for handle: 1"));
        };

        for (uid, value) in chains {
            if chain_table.contains_key(&uid) {
                ffi_bail!(format!("Conflict in Chain Table for UID: {uid:?}"));
            }
            chain_table.insert(uid, value);
        }

        0
    }
}

unsafe fn ffi_upsert(
    master_key: &[u8],
    label: &str,
    additions: HashMap<IndexedValue, HashSet<Keyword>>,
) -> c_int {
    let master_key_ptr = master_key.to_vec().as_mut_ptr().cast();
    let master_key_len = master_key.len() as c_int;

    let label_cs = CString::new(label).unwrap();
    let label_ptr = label_cs.as_ptr();

    let mut additions_bytes = serialize_indexed_values(additions).unwrap();
    let additions_ptr: *mut c_char = additions_bytes.as_mut_ptr().cast();
    let mut additions_len = additions_bytes.len() as c_int;
    let additions_len = &mut additions_len;
    ffi_write_bytes!("additions", &additions_bytes, additions_ptr, additions_len);

    let mut deletions_bytes = serialize_indexed_values(HashMap::new()).unwrap();
    println!("deletions_bytes: {deletions_bytes:?}");
    let deletions_ptr: *mut c_char = deletions_bytes.as_mut_ptr().cast();
    let mut deletions_len = deletions_bytes.len() as c_int;
    let deletions_len = &mut deletions_len;
    ffi_write_bytes!("deletions", &deletions_bytes, deletions_ptr, deletions_len);

    let ret = h_upsert(
        master_key_ptr,
        master_key_len,
        label_ptr.cast(),
        label.len() as i32,
        additions_ptr,
        deletions_ptr,
        1,
        FindexTest::fetch_entry,
        FindexTest::upsert_entry,
        FindexTest::insert_chain,
    );

    assert!(
        0 == ret,
        "FFI h_upsert function exit with error: {ret}, error message: {:?}",
        get_last_error()
    );

    0
}

unsafe fn ffi_search(master_key: &[u8], label: &str, keywords: HashSet<Keyword>) -> c_int {
    let master_key_ptr = master_key.to_vec().as_mut_ptr().cast();
    let master_key_len = master_key.len() as c_int;

    let label_cs = CString::new(label).unwrap();
    let label_ptr = label_cs.as_ptr();

    let mut keywords_base64 = HashSet::with_capacity(keywords.len());
    for keyword in &keywords {
        keywords_base64.insert(STANDARD.encode(keyword));
    }
    let keywords_json = serde_json::to_vec(&keywords_base64).unwrap();
    let keywords_ptr = keywords_json.as_ptr().cast();

    // OUTPUT
    let mut search_results = vec![0_u8; 131_072];
    let search_results_ptr = search_results.as_mut_ptr().cast();
    let mut search_results_len = search_results.len() as c_int;

    let ret = h_search(
        search_results_ptr,
        &mut search_results_len,
        master_key_ptr,
        master_key_len,
        label_ptr.cast(),
        label.len() as i32,
        keywords_ptr,
        1,
        FindexTest::progress,
        FindexTest::fetch_entry,
        FindexTest::fetch_chain,
    );

    assert!(
        0 == ret,
        "FFI h_search function exit with error: {ret}, error message: {:?}",
        get_last_error()
    );

    let search_results_bytes: &[u8] =
        ffi_read_bytes!("search_results", search_results_ptr, search_results_len);
    let results = deserialize_hashmap(search_results_bytes).unwrap();
    assert_eq!(results.len(), 1);
    0
}

#[test]

fn test_interfaces() {
    let master_key = vec![0u8; MASTER_KEY_LENGTH];
    let label = "my label";

    let mut additions = HashMap::new();
    // direct location robert doe
    let robert_location = Location::from("robert");
    additions.insert(
        IndexedValue::Location(robert_location),
        hashset_keywords(&["robert"]),
    );

    FindexTest::init();
    unsafe {
        let ret = ffi_upsert(&master_key, label, additions);
        assert!(
            0 == ret,
            "upsert function exit with error: {ret}, error message: {:?}",
            get_last_error()
        );
    }

    println!("entry_table_len: {:?}", get_entry_table().len());
    println!("chain_table_len: {:?}", get_chain_table().len());
    assert_eq!(get_entry_table().len(), 1);
    assert_eq!(get_chain_table().len(), 1);

    let robert_keyword = Keyword::from("robert");
    let keywords = HashSet::from_iter([robert_keyword]);

    unsafe {
        let ret = ffi_search(&master_key, label, keywords);
        assert!(
            0 == ret,
            "search function exit with error: {ret}, error message: {:?}",
            get_last_error()
        );
    }
}
