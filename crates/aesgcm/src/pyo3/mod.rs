use pyo3::{pymodule, types::PyModule, PyResult, Python};

use self::aesgcm::Aes256Gcm;

mod aesgcm;

/// A Python module implemented in Rust.
#[pymodule]
fn cloudproof_aesgcm(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Aes256Gcm>()?;

    Ok(())
}
