//! This crate implements the Findex interface for `SQlite`.
//! WARNING: compacting is not implemented yet.

mod error;
mod findex;
pub mod utils;

pub use error::Error;
pub use findex::SqliteFindex;
