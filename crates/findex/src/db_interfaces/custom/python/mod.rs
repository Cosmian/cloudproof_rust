use cosmian_findex::{ENTRY_LENGTH, LINK_LENGTH};

mod callbacks;

pub use callbacks::PythonCallbacks;

#[derive(Debug)]
pub struct PythonEntryBackend(PythonCallbacks);

impl_custom_backend!(PythonEntryBackend, PythonCallbacks, ENTRY_LENGTH);

#[derive(Debug)]
pub struct PythonChainBackend(PythonCallbacks);

impl_custom_backend!(PythonChainBackend, PythonCallbacks, LINK_LENGTH);
