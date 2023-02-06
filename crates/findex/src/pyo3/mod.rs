//! Defines the Python interface for Findex.

use py_api::InternalFindex;
use py_structs::{IndexedValue, Label, MasterKey};
use pyo3::prelude::*;

macro_rules! pyo3_unwrap {
    ($res:expr, $msg:literal) => {
        $res.map_err(|e| pyo3::exceptions::PyTypeError::new_err(format!("{}: {e}", $msg)))?
    };
}

mod py_api;
mod py_structs;

#[pymodule]
fn cloudproof_findex(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<InternalFindex>()?;
    m.add_class::<Label>()?;
    m.add_class::<MasterKey>()?;
    m.add_class::<IndexedValue>()?;
    Ok(())
}
