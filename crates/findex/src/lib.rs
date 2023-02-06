//! Findex allows for searching an encrypted data base. It is based on two
//! tables, namely the Entry Table and the Chain Table.
//!
//! The source code is structured as follows:
//! - the `core` module contains all the cryptographic APIs;
//! - the `interfaces` module contains interfaces with other languages.

// Rule MEM-FORGET (<https://anssi-fr.github.io/rust-guide/05_memory.html>):
// > In a secure Rust development, the forget function of std::mem (core::mem)
// must not be used.
#![deny(clippy::mem_forget)]
// Since asynchronous functions in traits are not yet stabilized in Rust
// `stable` toolchain, we are using the incomplete (but working) feature
// `async_fn_in_trait`:
// <https://rust-lang.github.io/rfcs/3185-static-async-fn-in-trait.html>.
// It allows the Wasm Findex implementation to reuse the common traits
// for searching and upserting indexes.
#![feature(async_fn_in_trait)]
#![feature(iter_next_chunk)]
#![allow(incomplete_features)]

//! Defines Findex interfaces for other languages.

mod error;
pub mod generic_parameters;

#[cfg(feature = "serde")]
pub mod ser_de;

#[cfg(feature = "cloud")]
pub mod cloud;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "python")]
pub mod pyo3;

#[cfg(feature = "wasm_bindgen")]
pub mod wasm_bindgen;

// This module is public because it is used for benchmarks.
#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(test)]
mod tests;
