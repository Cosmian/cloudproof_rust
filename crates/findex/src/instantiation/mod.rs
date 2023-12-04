//! This module provides components to easily instantiate a Findex object using
//! a given backend:
//!
//! - [`InstantiatedFindex`](InstantiatedFindex): Findex wrapper that provides
//!   Findex API;
//! - [`BackendConfiguration`](BackendConfiguration): configuration storing all
//!   information required to instantiate a given backend.
//!
//! ```txt
//! +-----------------------------------------------------------------+
//! | +-----------------------------------------+                     |
//! | | +----------+ +---------+     +--------+ | //                  |
//! | | | B. Redis | | B. HTTP | ... | B. FFI | | // Backend layer    |
//! | | +----------+ +---------+     +--------+ | //                  |
//! | +-----------------------------------------+                     |
//! | |             Findex instance             |                     |
//! | +-----------------------------------------+                     |
//! |              ^                ^                                 |
//! |              |                |                                 |
//! |      +---------------+      Findex                              |
//! |      | Configuration |       API                                |
//! |      +---------------+        |                                 |
//! |              |                v                                 |
//! |           ------------------------                              |
//! |          /           |            \                             |
//! |     +--------+ +---------+ +-----------+     //                 |
//! |     | I. FFI | | I. WASM | | I. Python |     // Interface layer |
//! |     +--------+ +---------+ +-----------+     //                 |
//! |                                                                 |
//! +-----------------------------------------------------------------+
//! |                         Cloudproof Rust                         |
//! +-----------------------------------------------------------------+
//!                                  ^
//!                                  |
//!                                  v
//! +-----------------------------------------------------------------+
//! |           Cloudproof Js/Python/Java/Flutter (optional)          |
//! +-----------------------------------------------------------------+
//!                                  ^
//!                                  |
//!                                  v
//! +-----------------------------------------------------------------+
//! |                            User Code                            |
//! +-----------------------------------------------------------------+
//! ```
//!
//! This split allows creating a neat abstraction of the backend and Findex
//! instantiation machinery, that can be used easily in the interface layer.
//!
//! This also has the advantage of gathering all instantiation information in a
//! single place.

mod db_config;
mod findex;

pub use db_config::Configuration;
pub use findex::InstantiatedFindex;
