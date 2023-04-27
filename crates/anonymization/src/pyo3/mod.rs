use pyo3::{pymodule, types::PyModule, PyResult, Python};

macro_rules! pyo3_unwrap {
    ($res:expr, $msg:literal) => {
        $res.map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}: {e:?}", $msg)))?
    };
}

mod py_hash;
use py_hash::Hasher;

mod py_noise;
use py_noise::NoiseGenerator;

mod py_word;
use py_word::{WordMasker, WordPatternMasker, WordTokenizer};

mod py_number;
use py_number::{DateAggregator, NumberAggregator, NumberScaler};

/// A Python module implemented in Rust.
#[pymodule]
fn cloudproof_anonymization(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Hasher>()?;
    m.add_class::<NoiseGenerator>()?;
    m.add_class::<WordMasker>()?;
    m.add_class::<WordPatternMasker>()?;
    m.add_class::<WordTokenizer>()?;
    m.add_class::<NumberAggregator>()?;
    m.add_class::<DateAggregator>()?;
    m.add_class::<NumberScaler>()?;

    Ok(())
}
