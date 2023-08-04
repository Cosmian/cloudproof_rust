#[cfg(not(feature = "wasm_bindgen"))]
use std::time::SystemTime;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    str::FromStr,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use cosmian_crypto_core::{bytes_ser_de::Serializable, reexport::rand_core::SeedableRng, CsRng};
use cosmian_findex::{
    kmac,
    parameters::{
        KmacKey, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KMAC_KEY_LENGTH, KWI_LENGTH, MASTER_KEY_LENGTH,
        UID_LENGTH,
    },
    CoreError as FindexCoreError, EncryptedMultiTable, EncryptedTable, FetchChains,
    FindexCallbacks, FindexSearch, FindexUpsert, IndexedValue, KeyingMaterial, Keyword, Location,
    Uids, UpsertData,
};
#[cfg(feature = "wasm_bindgen")]
use js_sys::Date;
use reqwest::Client;
#[cfg(feature = "wasm_bindgen")]
use wasm_bindgen::JsValue;

use super::ser_de::serialize_set;
use crate::ser_de::{deserialize_fetch_entry_table_results, SerializableSetError};

pub struct FindexCloud {
    pub(crate) token: Token,
    pub(crate) base_url: Option<String>,
}

/// See `Token@index_id`
pub const INDEX_ID_LENGTH: usize = 5;

/// The callback signature is a kmac of the body of the request.
/// It is used to assert the client can call this callback.
pub const CALLBACK_SIGNATURE_LENGTH: usize = 32;

/// The number of seconds of validity of the requests to the Findex Cloud
/// backend. After this time, the request cannot be accepted by the backend.
/// This is done to prevent replay attacks.
pub const REQUEST_SIGNATURE_TIMEOUT_AS_SECS: u64 = 60;

/// This seed is used to derive a new 32 bytes Kmac key.
pub const SIGNATURE_SEED_LENGTH: usize = 16;

pub const FINDEX_CLOUD_DEFAULT_DOMAIN: &str = "https://findex.cosmian.com";

#[derive(Debug)]
pub enum FindexCloudError {
    MalformedToken {
        error: String,
    },
    MissingPermission {
        permission: String,
    },
    Callback {
        error: String,
    },
    Findex {
        error: FindexCoreError,
    },
    Serialization {
        error: SerializableSetError,
    },
    #[cfg(not(feature = "wasm_bindgen"))]
    Other {
        error: String,
    },
}

#[cfg(feature = "ffi")]
impl crate::ffi::error::ToErrorCode for FindexCloudError {}

impl Display for FindexCloudError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedToken { error } => {
                write!(f, "token is malformed: {error}")
            }
            Self::MissingPermission { permission } => {
                write!(f, "token provided misses permission {permission}")
            }
            Self::Callback { error } => write!(f, "{error}"),
            Self::Findex { error } => write!(f, "Findex core error: {error}"),
            Self::Serialization { error } => write!(f, "serialization error: {error}"),
            #[cfg(not(feature = "wasm_bindgen"))]
            Self::Other { error } => write!(f, "{error}"),
        }
    }
}

impl From<FindexCoreError> for FindexCloudError {
    fn from(error: FindexCoreError) -> Self {
        Self::Findex { error }
    }
}

impl From<SerializableSetError> for FindexCloudError {
    fn from(value: SerializableSetError) -> Self {
        Self::Serialization { error: value }
    }
}

#[cfg(feature = "wasm_bindgen")]
impl From<FindexCloudError> for JsValue {
    fn from(value: FindexCloudError) -> Self {
        Self::from_str(&value.to_string())
    }
}

impl std::error::Error for FindexCloudError {}

impl cosmian_findex::CallbackError for FindexCloudError {}

/// Findex Cloud tokens are a string containing all information required to do
/// requests to Findex Cloud (except the label because it is a value changing a
/// lot).
///
/// The string is encoded as follow:
/// 1. `index_id` `INDEX_ID_LENGTH` chars (see `Token@index_id`)
/// 2. base64 representation of the different keys:
///     1. `MASTER_KEY_LENGTH` bytes of findex master key (this key is never
/// sent to the Findex Cloud backend)
///     2. 1 byte prefix identifying the next key
///     3. `SIGNATURE_SEED_LENGTH` bytes of callback signature key
///     4. 1 byte prefix identifying the next key
///     5. …
///
/// Currently each callback has an associated signature key used in a kmac to
/// send request to the backend. These key are only used for authorization
/// and do not secure the index (the findex master key do). In the future, we
/// could do optimization to avoid having one key for each callback but we want
/// to disallow the server to differentiate a `fetch_entries` for a search or a
/// `fetch_entries` for an upsert while still allowing fine grain permissions.
pub struct Token {
    /// This ID identifies an index inside the Findex Cloud backend
    /// This number is not sensitive, it's only an ID. If someone finds this ID,
    /// it cannot do requests on the index because it doesn't have the keys.
    /// We do not use auto-increment integer ID because we don't want to leak
    /// the number of indexes inside our database.
    /// We do not use UUID because the token is limited in space.
    /// The arbitrary chosen length is `INDEX_ID_LENGTH`.
    index_id: String,

    pub(crate) findex_master_key: KeyingMaterial<MASTER_KEY_LENGTH>,

    fetch_entries_seed: Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>,
    fetch_chains_seed: Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>,
    upsert_entries_seed: Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>,
    insert_chains_seed: Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>,
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut size = self.findex_master_key.len();
        for callback in Callback::ALL {
            size += self.get_seed(callback).map_or(0, |seed| seed.len() + 1);
        }

        let mut seeds = Vec::with_capacity(size);
        seeds.extend(self.findex_master_key.as_ref());

        for callback in Callback::ALL {
            if let Some(seed) = self.get_seed(callback) {
                seeds.push(callback as u8);
                seeds.extend(seed.as_ref());
            }
        }

        write!(f, "{}{}", self.index_id, STANDARD.encode(seeds))
    }
}

impl FromStr for Token {
    type Err = FindexCloudError;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        let (index_id, tail) = token.split_at(INDEX_ID_LENGTH);
        let mut bytes = STANDARD
            .decode(tail)
            .map_err(|e| FindexCloudError::MalformedToken {
                error: format!("the keys section is not base64 encoded ({e})"),
            })?
            .into_iter();
        let original_length = bytes.len();

        let findex_master_key =
            KeyingMaterial::deserialize(&bytes.next_chunk::<MASTER_KEY_LENGTH>().map_err(
                |e| FindexCloudError::MalformedToken {
                    error: format!(
                        "cannot read the Findex master key at the beginning of the keys section \
                         ({e:?})"
                    ),
                },
            )?)?;

        let mut token = Self {
            index_id: index_id.to_owned(),
            findex_master_key,

            fetch_entries_seed: None,
            fetch_chains_seed: None,
            upsert_entries_seed: None,
            insert_chains_seed: None,
        };

        while let Some(prefix) = bytes.next() {
            let seed = Some(
                bytes
                    .next_chunk::<SIGNATURE_SEED_LENGTH>()
                    .map_err(|_| FindexCloudError::MalformedToken {
                        error: format!(
                            "expecting {SIGNATURE_SEED_LENGTH} bytes after the prefix {prefix:?} \
                             at keys section offset {}",
                            original_length - bytes.len() - 1
                        ),
                    })?
                    .into(),
            );

            let callback: Callback =
                prefix
                    .try_into()
                    .map_err(|_| FindexCloudError::MalformedToken {
                        error: format!(
                            "unknown prefix {prefix:?} at keys section offset {}",
                            original_length - bytes.len() - 1
                        ),
                    })?;

            token.set_seed(callback, seed);
        }

        Ok(token)
    }
}

impl Token {
    pub fn random_findex_master_key(
        index_id: String,
        fetch_entries_seed: KeyingMaterial<SIGNATURE_SEED_LENGTH>,
        fetch_chains_seed: KeyingMaterial<SIGNATURE_SEED_LENGTH>,
        upsert_entries_seed: KeyingMaterial<SIGNATURE_SEED_LENGTH>,
        insert_chains_seed: KeyingMaterial<SIGNATURE_SEED_LENGTH>,
    ) -> Result<Self, FindexCloudError> {
        let mut rng = CsRng::from_entropy();
        let findex_master_key = KeyingMaterial::new(&mut rng);

        Ok(Self {
            index_id,
            findex_master_key,
            fetch_entries_seed: Some(fetch_entries_seed),
            fetch_chains_seed: Some(fetch_chains_seed),
            upsert_entries_seed: Some(upsert_entries_seed),
            insert_chains_seed: Some(insert_chains_seed),
        })
    }

    pub fn reduce_permissions(
        &mut self,
        search: bool,
        index: bool,
    ) -> Result<(), FindexCloudError> {
        self.fetch_entries_seed =
            reduce_option("fetch entries", &self.fetch_entries_seed, search || index)?;
        self.fetch_chains_seed = reduce_option("fetch chains", &self.fetch_chains_seed, search)?;
        self.upsert_entries_seed =
            reduce_option("upsert entries", &self.upsert_entries_seed, index)?;
        self.insert_chains_seed = reduce_option("insert chains", &self.insert_chains_seed, index)?;

        Ok(())
    }

    fn get_seed(&self, callback: Callback) -> Option<&KeyingMaterial<SIGNATURE_SEED_LENGTH>> {
        match callback {
            Callback::FetchEntries => &self.fetch_entries_seed,
            Callback::FetchChains => &self.fetch_chains_seed,
            Callback::UpsertEntries => &self.upsert_entries_seed,
            Callback::InsertChains => &self.insert_chains_seed,
        }
        .as_ref()
    }

    fn get_key(&self, callback: Callback) -> Option<KmacKey> {
        self.get_seed(callback)
            .map(|seed| seed.derive_kmac_key::<KMAC_KEY_LENGTH>(self.index_id.as_bytes()))
    }

    fn set_seed(
        &mut self,
        callback: Callback,
        seed: Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>,
    ) {
        match callback {
            Callback::FetchEntries => self.fetch_entries_seed = seed,
            Callback::FetchChains => self.fetch_chains_seed = seed,
            Callback::UpsertEntries => self.upsert_entries_seed = seed,
            Callback::InsertChains => self.insert_chains_seed = seed,
        }
    }
}

/// If we have the permission and want to keep it, do nothing.
/// If we don't have the permission and want to keep it, fail.
/// If we don't want to keep it, return none.
fn reduce_option(
    permission_name: &str,
    permission: &Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>,
    keep: bool,
) -> Result<Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>, FindexCloudError> {
    match (permission, keep) {
        (_, false) => Ok(None),
        (Some(permission), true) => Ok(Some(permission.clone())),
        (None, true) => Err(FindexCloudError::MissingPermission {
            permission: permission_name.to_string(),
        }),
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum Callback {
    FetchEntries = 0,
    FetchChains = 1,
    UpsertEntries = 2,
    InsertChains = 3,
}

impl Callback {
    const ALL: [Self; 4] = [
        Self::FetchEntries,
        Self::FetchChains,
        Self::UpsertEntries,
        Self::InsertChains,
    ];

    pub fn get_uri(self) -> &'static str {
        match self {
            Self::FetchEntries => "fetch_entries",
            Self::FetchChains => "fetch_chains",
            Self::UpsertEntries => "upsert_entries",
            Self::InsertChains => "insert_chains",
        }
    }
}

impl TryFrom<u8> for Callback {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::FetchEntries),
            1 => Ok(Self::FetchChains),
            2 => Ok(Self::UpsertEntries),
            3 => Ok(Self::InsertChains),
            _ => Err(()),
        }
    }
}

impl Display for Callback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FetchEntries => write!(f, "fetch entries"),
            Self::FetchChains => write!(f, "fetch chains"),
            Self::UpsertEntries => write!(f, "upsert entries"),
            Self::InsertChains => write!(f, "insert chains"),
        }
    }
}

impl FindexCloud {
    pub fn new(token: &str, base_url: Option<String>) -> Result<Self, FindexCloudError> {
        Ok(Self {
            token: Token::from_str(token)?,
            base_url,
        })
    }

    async fn post(&self, callback: Callback, bytes: Vec<u8>) -> Result<Vec<u8>, FindexCloudError> {
        let key =
            self.token
                .get_key(callback)
                .ok_or_else(|| FindexCloudError::MissingPermission {
                    permission: callback.to_string(),
                })?;

        // SystemTime::now() panics in WASM <https://github.com/rust-lang/rust/issues/48564>
        #[cfg(feature = "wasm_bindgen")]
        let current_timestamp = (Date::now() / 1000.0) as u64; // Date::now() returns milliseconds

        #[cfg(not(feature = "wasm_bindgen"))]
        let current_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| FindexCloudError::Other {
                error: "SystemTime is before UNIX_EPOCH".to_string(),
            })?
            .as_secs();

        let expiration_timestamp_bytes =
            (current_timestamp + REQUEST_SIGNATURE_TIMEOUT_AS_SECS).to_be_bytes();

        let signature = kmac!(
            CALLBACK_SIGNATURE_LENGTH,
            &key,
            &expiration_timestamp_bytes,
            &bytes
        );

        let mut body =
            Vec::with_capacity(signature.len() + expiration_timestamp_bytes.len() + bytes.len());
        body.extend_from_slice(&signature);
        body.extend_from_slice(&expiration_timestamp_bytes);
        body.extend_from_slice(&bytes);

        let url = format!(
            "{}/indexes/{}/{}",
            self.base_url
                .as_deref()
                .unwrap_or(FINDEX_CLOUD_DEFAULT_DOMAIN),
            self.token.index_id,
            callback.get_uri(),
        );

        let response = Client::new()
            .post(url)
            .body(body)
            .send()
            .await
            .map_err(|err| FindexCloudError::Callback {
                error: format!("Unable to send the request to FindexCloud: {err}"),
            })?;

        if !response.status().is_success() {
            return Err(FindexCloudError::Callback {
                error: format!(
                    "request to Findex Cloud failed, status code is {}, response is {}",
                    response.status(),
                    response
                        .text()
                        .await
                        .unwrap_or_else(|_| "cannot parse response".to_owned())
                ),
            });
        }

        Ok(response
            .bytes()
            .await
            .map_err(|err| FindexCloudError::Callback {
                error: format!("Impossible to read the returned bytes from FindexCloud:  {err}"),
            })?
            .to_vec())
    }
}

impl FindexCallbacks<FindexCloudError, UID_LENGTH> for FindexCloud {
    async fn progress(
        &self,
        _results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, FindexCloudError> {
        Ok(true)
    }

    async fn fetch_all_entry_table_uids(&self) -> Result<Uids<UID_LENGTH>, FindexCloudError> {
        Err(FindexCloudError::Callback {
            error: "fetch all entry table uids not implemented in WASM".to_string(),
        })
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedMultiTable<UID_LENGTH>, FindexCloudError> {
        let serialized_uids = serialize_set(&entry_table_uids.0)?;

        let bytes = self.post(Callback::FetchEntries, serialized_uids).await?;

        Ok(EncryptedMultiTable(deserialize_fetch_entry_table_results(
            &bytes,
        )?))
    }

    async fn fetch_chain_table(
        &self,
        chain_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexCloudError> {
        let serialized_uids = serialize_set(&chain_table_uids.0)?;

        let bytes = self.post(Callback::FetchChains, serialized_uids).await?;

        EncryptedTable::deserialize(&bytes).map_err(FindexCloudError::from)
    }

    async fn upsert_entry_table(
        &self,
        items: UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexCloudError> {
        let serialized_upsert = items.serialize()?;

        let bytes = self
            .post(Callback::UpsertEntries, serialized_upsert.to_vec())
            .await?;

        EncryptedTable::deserialize(&bytes).map_err(FindexCloudError::from)
    }

    async fn insert_chain_table(
        &self,
        items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexCloudError> {
        let serialized_insert = items.serialize()?;

        self.post(Callback::InsertChains, serialized_insert.to_vec())
            .await?;

        Ok(())
    }

    async fn update_lines(
        &self,
        _chain_table_uids_to_remove: Uids<UID_LENGTH>,
        _new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        _new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexCloudError> {
        Err(FindexCloudError::Callback {
            error: "update lines not implemented in WASM".to_string(),
        })
    }

    async fn list_removed_locations(
        &self,
        _locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexCloudError> {
        Err(FindexCloudError::Callback {
            error: "list removed locations not implemented in WASM".to_string(),
        })
    }
}

impl FetchChains<UID_LENGTH, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KWI_LENGTH, FindexCloudError>
    for FindexCloud
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
        FindexCloudError,
    > for FindexCloud
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
        FindexCloudError,
    > for FindexCloud
{
}
