use pyo3::{pymodule, types::PyModule, PyResult, Python};

macro_rules! pyo3_unwrap {
    ($res:expr, $msg:literal) => {
        $res.map_err(|e| pyo3::exceptions::PyTypeError::new_err(format!("{}: {e:?}", $msg)))?
    };
}

mod py_hash;
use py_hash::Hasher;

mod py_noise;
use py_noise::NoiseGenerator;

/// A Python module implemented in Rust.
#[pymodule]
fn cloudproof_anonymization(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Hasher>()?;
    m.add_class::<NoiseGenerator>()?;
    Ok(())
}
