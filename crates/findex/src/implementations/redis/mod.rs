// This is required at the top level to support Findex
// #![feature(async_fn_in_trait)]

mod callbacks;
mod error;
mod findex;

pub use callbacks::RemovedLocationsFinder;
pub use cosmian_findex::{parameters::MASTER_KEY_LENGTH, IndexedValue, Keyword, Location};
pub use error::FindexRedisError;
pub use findex::FindexRedis;
