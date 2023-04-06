use pyo3::{pymodule, types::PyModule, PyResult, Python};

use self::{py_alphabet::Alphabet, py_float::Float, py_integer::Integer};

mod py_alphabet;
mod py_float;
mod py_integer;

/// A Python module implemented in Rust.
#[pymodule]
fn cloudproof_fpe(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Alphabet>()?;
    m.add_class::<Integer>()?;
    m.add_class::<Float>()?;
    Ok(())
}
