//! Redis implementation of the Findex backends.

use std::{
    fmt::{self, Debug, Display},
    hash::Hash,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use redis::{Commands, Connection, Script, ToRedisArgs};

use crate::db_interfaces::DbInterfaceError;
use findex::MemoryADT;

#[derive(Clone)]
pub struct RedisBackend<Address: Hash + Eq, const WORD_LENGTH: usize> {
    connection: Arc<Mutex<Connection>>,
    // TODO : send script to redis and keep only the hash for invocations
    write_script: Script,
    _marker_adr: PhantomData<Address>,
}

// Args that are passed to the LUA script are, in order:
// 1. Guard address.
// 2. Guard value.
// 3. Vector length.
// 4+. Vector elements (address, word).
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

const POISONED_LOCK_ERROR_MSG: &str = "Poisoned lock error";

impl<Address: Hash + Eq, const WORD_LENGTH: usize> Debug for RedisBackend<Address, WORD_LENGTH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisMemory")
            .field("connection", &"<redis::Connection>") // We don't want to debug the actual connection
            .field("Addr type", &self._marker_adr)
            .finish()
    }
}

impl<Address: Hash + Eq, const WORD_LENGTH: usize> RedisBackend<Address, WORD_LENGTH> {
    /// Connects to a Redis server using the given URL.
    pub async fn connect(url: &str) -> Result<Self, DbInterfaceError> {
        Ok(Self {
            connection: match redis::Client::open(url) {
                Ok(client) => match client.get_connection() {
                    Ok(con) => Arc::new(Mutex::new(con)),
                    Err(e) => {
                        panic!("Failed to connect to Redis: {}", e);
                    }
                },
                Err(e) => panic!("Error creating redis client: {:?}", e),
            },
            write_script: Script::new(GUARDED_WRITE_LUA_SCRIPT),
            _marker_adr: PhantomData,
        })
    }

    // TODO : manager is not compatible with the return types of memoryADT
    // should we keep it ?
    /// Connects to a Redis server with a `ConnectionManager`.
    // pub async fn connect_with_manager(
    //     manager: ConnectionManager,
    // ) -> Result<Self, DbInterfaceError> {
    //     Ok(Self {
    //         connection: Arc::new(Mutex::new(manager)),
    //         write_script: Script::new(GUARDED_WRITE_LUA_SCRIPT),
    //         _marker_adr: PhantomData,
    //         _marker_value: PhantomData,
    //     })
    // }

    /// Clear all indexes
    ///
    /// # Warning
    /// This is definitive
    // pub async fn clear_indexes(&self) -> Result<(), DbInterfaceError> {
    //     redis::cmd("FLUSHDB")
    //         .query_async::<()>(&mut self.connection.lock().expect(POISONED_LOCK_ERROR_MSG) // explicitly setting <()> solves the following problem https://github.com/rust-lang/rust/issues/123748
    //         .await?;
    //     Ok(())
    // }

    pub fn clear_indexes(&self) -> Result<(), redis::RedisError> {
        let safe_connection = &mut *self.connection.lock().expect(POISONED_LOCK_ERROR_MSG);
        redis::cmd("FLUSHDB").exec(safe_connection)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisMemoryError(String);

impl std::error::Error for RedisMemoryError {}

impl From<redis::RedisError> for RedisMemoryError {
    fn from(err: redis::RedisError) -> Self {
        Self(err.to_string())
    }
}

impl Display for RedisMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Redis Memory Error: {}", self.0)
    }
}

impl<Address: Send + Sync + Hash + Eq + Debug + Clone + ToRedisArgs, const WORD_LENGTH: usize>
    MemoryADT for RedisBackend<Address, WORD_LENGTH>
{
    type Address = Address;
    type Error = RedisMemoryError;
    type Word = [u8; WORD_LENGTH];

    async fn batch_read(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        let safe_connection = &mut *self.connection.lock().expect(POISONED_LOCK_ERROR_MSG);
        let refs: Vec<&Address> = addresses.iter().collect::<Vec<&Address>>(); // Redis MGET requires references to the values
        safe_connection
            .mget::<_, Vec<_>>(&refs)
            .map_err(Self::Error::from)
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let mut safe_connection = self.connection.lock().expect(POISONED_LOCK_ERROR_MSG);
        let (guard_address, guard_value) = guard;

        let mut script_invocation = self.write_script.prepare_invoke();

        script_invocation.arg(guard_address);
        if let Some(byte_array) = guard_value {
            script_invocation.arg(&byte_array);
        } else {
            script_invocation.arg("false".to_string());
        }
        script_invocation.arg(bindings.len());
        for (address, word) in bindings {
            script_invocation.arg(address).arg(&word);
        }

        script_invocation
            .invoke(&mut safe_connection)
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {

    use futures::executor::block_on;
    use serial_test::serial;
    use tracing::trace;

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
    async fn test_read_write() -> Result<(), DbInterfaceError> {
        // L'idée c'est de vérifier qu'une modification est rejetée si le gard n'est pas le bon.

        let memory = RedisBackend::<u8, 1>::connect(&get_redis_url())
            .await
            .unwrap();
        memory.clear_indexes().unwrap();

        assert_eq!(
            block_on(memory.guarded_write((0, None), vec![(6, [9])])).unwrap(),
            None
        );

        assert_eq!(
            block_on(memory.guarded_write((0, None), vec![(0, [2]), (1, [1]), (2, [1])])).unwrap(),
            None
        );

        assert_eq!(
            block_on(memory.guarded_write((0, None), vec![(0, [4]), (3, [2]), (4, [2])])).unwrap(),
            Some([2]) // should return Some([2]), indicating that the guard (None) failed
        );

        assert_eq!(
            block_on(memory.guarded_write((0, Some([2])), vec![(0, [4]), (3, [3]), (4, [3])]))
                .unwrap(),
            Some([2])
        );

        assert_eq!(
            vec![Some([1]), Some([1]), Some([3]), Some([3])],
            block_on(memory.batch_read(vec![1, 2, 3, 4])).unwrap(),
        );
        Ok(())
    }

    #[actix_rt::test]
    #[serial]
    #[ignore]
    async fn test_parallel() -> Result<(), DbInterfaceError> {
        // spawner bcp d'acteurs qui frappent sur la db ensemble
        // check this - branch epub
        // Concurrently adding data to instances of the same vector should not introduce data loss.
        //  pub async fn test_vector_concurrent<
        Ok(())
    }

    // TODO legacy test, à revoir
    #[actix_rt::test]
    #[serial]
    #[ignore]
    async fn test_redis_backend() {
        log_init();
        trace!("Test Redis backend.");

        let url = get_redis_url();

        {
            let memory_to_flush = RedisBackend::<u8, 1>::connect(url.as_str()).await.unwrap();
            memory_to_flush.clear_indexes().unwrap();
        }

        let config: Configuration = Configuration::Redis(url.clone());
        test_backend(config).await;
    }
}
