//! Defines Findex interfaces for other languages.

#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]
#![cfg_attr(any(feature = "wasm", feature = "ffi"), feature(const_option))]
#![cfg_attr(feature = "cloud", feature(iter_next_chunk))]

pub mod ser_de;

#[cfg(feature = "cloud")]
pub mod cloud;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "python")]
pub mod pyo3;

#[cfg(feature = "wasm")]
pub mod wasm_bindgen;

#[cfg(any(feature = "wasm", feature = "ffi"))]
use core::num::NonZeroUsize;

#[cfg(any(feature = "wasm", feature = "ffi"))]
/// Default number of results returned per keyword.
pub const MAX_RESULTS_PER_KEYWORD: NonZeroUsize = NonZeroUsize::new(65536).unwrap();
