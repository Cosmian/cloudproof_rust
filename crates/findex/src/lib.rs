//! Defines Findex interfaces for other languages.

#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]
#![cfg_attr(any(feature = "wasm_bindgen", feature = "ffi"), feature(const_option))]
#![cfg_attr(feature = "cloud", feature(iter_next_chunk))]

pub mod ser_de;

#[cfg(feature = "cloud")]
pub mod cloud;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "python")]
pub mod pyo3;

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "wasm_bindgen")]
pub mod wasm_bindgen;
