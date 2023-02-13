#[macro_export]
macro_rules! pyo3_unwrap {
    ($result: expr) => {
        $result.map_err(|e| PyTypeError::new_err(e.to_string()))?
    };
}
