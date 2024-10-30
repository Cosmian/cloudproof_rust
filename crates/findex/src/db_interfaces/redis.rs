//! Redis implementation of the Findex backends.

use std::{collections::HashMap, sync::{Arc, Mutex}};

use async_trait::async_trait;
use cosmian_findex::{
    CoreError as FindexCoreError, DbInterface, EncryptedValue, Token, TokenToEncryptedValueMap,
    TokenWithEncryptedValueList, Tokens, ENTRY_LENGTH, LINK_LENGTH,
};
use redis::{aio::ConnectionManager, pipe, AsyncCommands, Script, ConnectionManager};
use tracing::trace;

use crate::db_interfaces::DbInterfaceError;
use findex::MemoryADT;



pub struct RedisBackend {
    // TODO verify if those need to be in a mutex ?
    connection: Arc<Mutex<ConnectionManager>>,
    write_script: Script,
}

impl std::fmt::Debug for RedisBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisBackend").finish()
    }
}

impl RedisBackend {
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


/**
 * Atomically writes the bindings if the guard is still valid.
 * Returns the current value on the guard's address.
 * If the result is equal to the guard's old value, the bindings get
 * written.
 *
 * Args that are passed to the LUA script are, in order :
 * 1. Guard address.
 * 2. Guard value.
 * 3. Vector length.
 * 4+. Vector elements (address, word).
 */
const GUARDED_WRITE_LUA_SCRIPT: &str = r#"
local guard_address = ARGV[1]
local guard_value = ARGV[2]
local length = ARGV[3]

local value = redis.call('GET',ARGV[1])

-- compare the value of the guard to the currently stored value
if((value==false) or (not(value == false) and (guard_value == value))) then
    -- guard passed, loop over bindings and insert them
    for i = 4,(length*2)+3,2
    do
        redis.call('SET', ARGV[i], ARGV[i+1])
    end
end
return value
"#;





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
