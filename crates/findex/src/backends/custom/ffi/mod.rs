use cosmian_findex::{ENTRY_LENGTH, LINK_LENGTH};

mod callbacks;

pub use callbacks::*;

#[derive(Debug)]
pub struct FfiEntryBackend(FfiCallbacks);

impl_custom_backend!(FfiEntryBackend, FfiCallbacks, ENTRY_LENGTH);

#[derive(Debug)]
pub struct FfiChainBackend(FfiCallbacks);

impl_custom_backend!(FfiChainBackend, FfiCallbacks, LINK_LENGTH);
