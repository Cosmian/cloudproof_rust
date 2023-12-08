//! Defines the Python interface for Findex.

#[macro_use]
mod macros;
mod api;
mod types;

use api::Findex;
use pyo3::prelude::*;
use types::{Key, Keyword, Label, Location};

use self::types::AuthorizationToken;
use crate::db_interfaces::custom::python::PythonCallbacks;

#[pymodule]
fn cloudproof_findex(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Findex>()?;
    m.add_class::<Label>()?;
    m.add_class::<Key>()?;
    m.add_class::<Location>()?;
    m.add_class::<Keyword>()?;
    m.add_class::<PythonCallbacks>()?;
    m.add_class::<AuthorizationToken>()
}
