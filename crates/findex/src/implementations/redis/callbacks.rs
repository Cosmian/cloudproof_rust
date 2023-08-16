use std::collections::HashSet;

use async_trait::async_trait;
use cosmian_findex::Location;

use super::FindexRedisError;

#[async_trait]
pub trait RemovedLocationsFinder {
    async fn find_removed_locations(
        &self,
        locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexRedisError>;
}
