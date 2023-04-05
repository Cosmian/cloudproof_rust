use pyo3::{pymodule, types::PyModule, PyResult, Python};

/// A Python module implemented in Rust.
#[pymodule]
fn cloudproof_anonymization(_py: Python, _m: &PyModule) -> PyResult<()> {
    Ok(())
}
