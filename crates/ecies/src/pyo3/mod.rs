use pyo3::{pymodule, types::PyModule, PyResult, Python};

use self::ecies::Ecies;

mod ecies;

/// A Python module implemented in Rust.
#[pymodule]
fn cloudproof_ecies(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Ecies>()?;

    Ok(())
}
