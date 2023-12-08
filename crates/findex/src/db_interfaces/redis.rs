//! Redis implementation of the Findex backends.

use std::collections::HashMap;

use async_trait::async_trait;
use cosmian_findex::{
    CoreError as FindexCoreError, DbInterface, EncryptedValue, Token, TokenToEncryptedValueMap,
    TokenWithEncryptedValueList, Tokens, ENTRY_LENGTH, LINK_LENGTH,
};
use redis::{aio::ConnectionManager, pipe, AsyncCommands, Script};
use tracing::trace;

use crate::db_interfaces::DbInterfaceError;

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
fn build_key(table: FindexTable, uid: &[u8]) -> Vec<u8> {
    [&[0x00, table as u8], uid].concat()
}

pub struct RedisEntryBackend {
    manager: ConnectionManager,
    upsert_script: Script,
}

impl std::fmt::Debug for RedisEntryBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisEntryBackend").finish()
    }
}

/// The conditional upsert script used to only update a table if the
/// indexed value matches ARGV[2]. When the value does not match, the
/// indexed value is returned.
const CONDITIONAL_UPSERT_SCRIPT: &str = r"
        local value=redis.call('GET',ARGV[1])
        if((value==false) or (not(value == false) and (ARGV[2] == value))) then
            redis.call('SET', ARGV[1], ARGV[3])
            return
        else
            return value
        end;
    ";

impl RedisEntryBackend {
    /// Connects to a Redis server using the given URL.
    pub async fn connect(url: &str) -> Result<Self, DbInterfaceError> {
        let client = redis::Client::open(url)?;
        let manager = ConnectionManager::new(client).await?;

        Ok(Self {
            manager,
            upsert_script: Script::new(CONDITIONAL_UPSERT_SCRIPT),
        })
    }

    /// Connects to a Redis server with a `ConnectionManager`.
    pub async fn connect_with_manager(
        manager: ConnectionManager,
    ) -> Result<Self, DbInterfaceError> {
        Ok(Self {
            manager,
            upsert_script: Script::new(CONDITIONAL_UPSERT_SCRIPT),
        })
    }

    /// Clear all indexes
    ///
    /// # Warning
    /// This is definitive
    pub async fn clear_indexes(&self) -> Result<(), DbInterfaceError> {
        redis::cmd("FLUSHDB")
            .query_async(&mut self.manager.clone())
            .await?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl DbInterface<ENTRY_LENGTH> for RedisEntryBackend {
    type Error = DbInterfaceError;

    async fn dump_tokens(&self) -> Result<Tokens, Self::Error> {
        let keys: Vec<Vec<u8>> = self
            .manager
            .clone()
            .keys(build_key(FindexTable::Entry, b"*"))
            .await?;

        trace!("dumping {} keywords (ET+CT)", keys.len());

        keys.iter()
            .filter_map(|v| {
                if v[..TABLE_PREFIX_LENGTH] == [0x00, FindexTable::Entry as u8] {
                    Some(Token::try_from(&v[TABLE_PREFIX_LENGTH..]).map_err(Self::Error::Findex))
                } else {
                    None
                }
            })
            .collect()
    }

    async fn fetch(
        &self,
        tokens: Tokens,
    ) -> Result<TokenWithEncryptedValueList<ENTRY_LENGTH>, Self::Error> {
        trace!("fetch_entry_table num keywords: {}:", tokens.len());

        if tokens.is_empty() {
            return Ok(Default::default());
        }

        // Collect into a vector to fix the order.
        let uids = tokens.into_iter().collect::<Vec<_>>();

        let redis_keys = uids
            .iter()
            .map(|uid| build_key(FindexTable::Entry, uid))
            .collect::<Vec<_>>();

        let values: Vec<Vec<u8>> = self.manager.clone().mget(redis_keys).await?;

        // Zip and filter empty values out.
        let res = uids
            .into_iter()
            .zip(values)
            .filter_map(|(k, v)| {
                if v.is_empty() {
                    None
                } else {
                    Some(EncryptedValue::try_from(v.as_slice()).map(|v| (k, v)))
                }
            })
            .collect::<Result<Vec<_>, FindexCoreError>>()?;

        trace!("fetch_entry_table non empty tuples len: {}", res.len());

        Ok(res.into())
    }

    async fn upsert(
        &self,
        old_values: TokenToEncryptedValueMap<ENTRY_LENGTH>,
        new_values: TokenToEncryptedValueMap<ENTRY_LENGTH>,
    ) -> Result<TokenToEncryptedValueMap<ENTRY_LENGTH>, Self::Error> {
        trace!("upsert_entry_table num keywords {:?}", new_values.len());

        let mut rejected = HashMap::with_capacity(new_values.len());
        for (uid, new_value) in new_values {
            let new_value = Vec::from(&new_value);
            let old_value = old_values.get(&uid).map(Vec::from).unwrap_or_default();
            let key = build_key(FindexTable::Entry, &uid);

            let indexed_value: Vec<_> = self
                .upsert_script
                .arg(key)
                .arg(old_value)
                .arg(new_value)
                .invoke_async(&mut self.manager.clone())
                .await?;

            if !indexed_value.is_empty() {
                let encrypted_value = EncryptedValue::try_from(indexed_value.as_slice())?;
                rejected.insert(uid, encrypted_value);
            }
        }

        trace!("upsert_entry_table rejected: {}", rejected.len());

        Ok(rejected.into())
    }

    async fn insert(
        &self,
        items: TokenToEncryptedValueMap<ENTRY_LENGTH>,
    ) -> Result<(), Self::Error> {
        let mut pipe = pipe();
        for (token, value) in &*items {
            pipe.set(build_key(FindexTable::Entry, token), Vec::from(value));
        }
        pipe.atomic()
            .query_async(&mut self.manager.clone())
            .await
            .map_err(Self::Error::from)
    }

    async fn delete(&self, entry_uids: Tokens) -> Result<(), Self::Error> {
        let mut pipeline = pipe();
        for uid in entry_uids {
            pipeline.del(build_key(FindexTable::Entry, &uid));
        }
        pipeline
            .atomic()
            .query_async(&mut self.manager.clone())
            .await
            .map_err(Self::Error::from)
    }
}

pub struct RedisChainBackend(ConnectionManager);

impl std::fmt::Debug for RedisChainBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RedisChainBackend").finish()
    }
}

impl RedisChainBackend {
    /// Connects to a Redis server using the given `url`.
    pub async fn connect(url: &str) -> Result<Self, DbInterfaceError> {
        let client = redis::Client::open(url)?;
        let manager = ConnectionManager::new(client).await?;
        Ok(Self(manager))
    }

    /// Connects to a Redis server with a `ConnectionManager`.
    pub async fn connect_with_manager(
        manager: ConnectionManager,
    ) -> Result<Self, DbInterfaceError> {
        Ok(Self(manager))
    }

    /// Clear all indexes
    ///
    /// # Warning
    /// This is definitive
    pub async fn clear_indexes(&self) -> Result<(), DbInterfaceError> {
        redis::cmd("FLUSHDB")
            .query_async(&mut self.0.clone())
            .await?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl DbInterface<LINK_LENGTH> for RedisChainBackend {
    type Error = DbInterfaceError;

    async fn dump_tokens(&self) -> Result<Tokens, Self::Error> {
        panic!("No token dump is performed for the Chain Table.")
    }

    async fn fetch(
        &self,
        tokens: Tokens,
    ) -> Result<TokenWithEncryptedValueList<LINK_LENGTH>, Self::Error> {
        trace!("fetch_entry_table num keywords: {}:", tokens.len());
        if tokens.is_empty() {
            return Ok(Default::default());
        }

        let uids = tokens.into_iter().collect::<Vec<_>>();
        let redis_keys = uids
            .iter()
            .map(|uid| build_key(FindexTable::Chain, uid))
            .collect::<Vec<_>>();

        let values: Vec<Vec<u8>> = self.0.clone().mget(redis_keys).await?;

        // Zip and filter empty values out.
        let res = uids
            .into_iter()
            .zip(values)
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| Ok((k, EncryptedValue::try_from(v.as_slice())?)))
            .collect::<Result<Vec<_>, Self::Error>>()?;

        trace!("fetch_entry_table non empty tuples len: {}", res.len());

        Ok(res.into())
    }

    async fn upsert(
        &self,
        _old_values: TokenToEncryptedValueMap<LINK_LENGTH>,
        _new_values: TokenToEncryptedValueMap<LINK_LENGTH>,
    ) -> Result<TokenToEncryptedValueMap<LINK_LENGTH>, Self::Error> {
        panic!("No token upsert is performed for the Chain Table.")
    }

    async fn insert(
        &self,
        items: TokenToEncryptedValueMap<LINK_LENGTH>,
    ) -> Result<(), Self::Error> {
        let mut pipe = pipe();
        for (k, v) in &*items {
            pipe.set(build_key(FindexTable::Chain, k), Vec::from(v));
        }
        pipe.atomic()
            .query_async(&mut self.0.clone())
            .await
            .map_err(Self::Error::from)
    }

    async fn delete(&self, chain_uids: Tokens) -> Result<(), Self::Error> {
        let mut pipeline = pipe();
        for uid in chain_uids {
            pipeline.del(build_key(FindexTable::Chain, &uid));
        }
        pipeline
            .atomic()
            .query_async(&mut self.0.clone())
            .await
            .map_err(Self::Error::from)
    }
}

#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use cosmian_crypto_core::{CsRng, Nonce};
    use cosmian_findex::{MAC_LENGTH, NONCE_LENGTH};
    use rand::{RngCore, SeedableRng};
    use serial_test::serial;

    use super::*;
    use crate::{db_interfaces::tests::test_backend, logger::log_init, Configuration};

    pub fn get_redis_url() -> String {
        if let Ok(var_env) = std::env::var("REDIS_HOST") {
            format!("redis://{var_env}:6379")
        } else {
            "redis://localhost:6379".to_string()
        }
    }

    #[actix_rt::test]
    #[serial]
    async fn test_upsert_conflict() -> Result<(), DbInterfaceError> {
        log_init();
        trace!("Test Redis upsert.");

        let mut rng = CsRng::from_entropy();

        // Generate 333 random UIDs.
        let mut uids = HashSet::with_capacity(333);
        while uids.len() < 333 {
            let mut uid = [0_u8; Token::LENGTH];
            rng.fill_bytes(&mut uid);
            uids.insert(uid);
        }
        let uids = uids.into_iter().collect::<Vec<_>>();

        let original_value = EncryptedValue {
            nonce: Nonce::from([0; NONCE_LENGTH]),
            ciphertext: [1; ENTRY_LENGTH],
            tag: [0; MAC_LENGTH],
        };
        let changed_value = EncryptedValue {
            nonce: Nonce::from([0; NONCE_LENGTH]),
            ciphertext: [2; ENTRY_LENGTH],
            tag: [0; MAC_LENGTH],
        };
        let new_value = EncryptedValue {
            nonce: Nonce::from([0; NONCE_LENGTH]),
            ciphertext: [2; ENTRY_LENGTH],
            tag: [0; MAC_LENGTH],
        };

        let url = get_redis_url();
        let et = RedisEntryBackend::connect(&url).await?;
        et.clear_indexes().await?;

        // First user upserts `original_value` to all the UIDs.
        let rejected = et
            .upsert(
                HashMap::new().into(),
                uids.iter()
                    .map(|k| (Token::from(*k), original_value.clone()))
                    .collect(),
            )
            .await?;
        assert!(rejected.is_empty());

        let et_length = et.dump_tokens().await?.len();
        trace!("Entry Table length: {et_length}");

        // Another user upserts `changed_value` to 111 UIDs.
        let rejected = et
            .upsert(
                uids.iter()
                    .map(|k| (Token::from(*k), original_value.clone()))
                    .collect(),
                uids.iter()
                    .enumerate()
                    .map(|(idx, k)| {
                        if idx % 3 == 0 {
                            (Token::from(*k), changed_value.clone())
                        } else {
                            (Token::from(*k), original_value.clone())
                        }
                    })
                    .collect(),
            )
            .await?;
        assert!(rejected.is_empty());

        let et_length = et.dump_tokens().await?.len();
        println!("Entry Table length: {et_length}");

        // The first user upserts `new_value` to all the UIDs from `original_value`. 111
        // UIDs should conflict.
        let rejected = et
            .upsert(
                uids.iter()
                    .map(|k| (Token::from(*k), original_value.clone()))
                    .collect(),
                uids.iter()
                    .map(|k| (Token::from(*k), new_value.clone()))
                    .collect(),
            )
            .await?;
        assert_eq!(111, rejected.len());
        for prev_value in rejected.values() {
            assert_eq!(prev_value, &changed_value);
        }

        // The firs user upserts `new_value` to the 111 rejected UIDs from
        // `changed_value`.
        let rejected = et
            .upsert(
                rejected.clone(),
                rejected.keys().map(|k| (*k, new_value.clone())).collect(),
            )
            .await?;
        assert_eq!(0, rejected.len());

        Ok(())
    }

    #[actix_rt::test]
    #[serial]
    async fn test_redis_backend() {
        log_init();
        trace!("Test Redis backend.");

        let url = get_redis_url();

        // Empty the Redis to prevent old ciphertexts to cause error during compacting.
        let client = redis::Client::open(url.as_str()).unwrap();
        let mut manager = ConnectionManager::new(client).await.unwrap();
        redis::cmd("FLUSHDB")
            .query_async::<_, ()>(&mut manager)
            .await
            .unwrap();

        let config = Configuration::Redis(url.clone(), url.clone());
        test_backend(config).await;
    }
}
