#[macro_export]
macro_rules! pyo3_unwrap {
    ($res: expr, $msg: literal) => {
        $res.map_err(|e| PyTypeError::new_err(format!("{}: {e:?}", $msg)))?
    };
}
