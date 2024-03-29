macro_rules! pyo3_unwrap {
    ($res:expr, $msg:literal) => {
        $res.map_err(|e| pyo3::exceptions::PyTypeError::new_err(format!("{}: {e}", $msg)))?
    };
}

/// Implements the basic functionalities of keyword and data in python.
///
/// # Parameters
///
/// - `py_type`   : name of the python type
/// - `rust_type` : name of the wrapped rust type
/// - `name`      : name of the class to appear in prints
macro_rules! impl_python_byte {
    ($py_type:ty, $rust_type:ty, $name:literal) => {
        #[pymethods]
        impl $py_type {
            /// Create from bytes.
            #[staticmethod]
            pub fn from_bytes(val: &[u8]) -> Self {
                Self(<$rust_type>::from(val))
            }

            /// Create from string.
            #[staticmethod]
            pub fn from_string(val: &str) -> Self {
                Self(<$rust_type>::from(val))
            }

            /// Create from int.
            #[staticmethod]
            pub fn from_int(val: i64) -> Self {
                Self(<$rust_type>::from(val.to_be_bytes().to_vec()))
            }

            /// Converts to string.
            fn __str__(&self) -> PyResult<String> {
                match String::from_utf8(self.0.to_vec()) {
                    Ok(s) => Ok(s),
                    Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e.to_string())),
                }
            }

            /// Converts to bytes.
            fn __bytes__(&self, py: Python) -> Py<PyBytes> {
                PyBytes::new(py, &self.0).into()
            }

            /// Converts to int.
            fn __int__(&self) -> PyResult<i64> {
                let arr: [u8; 8] = self.0.as_ref().try_into()?;
                Ok(i64::from_be_bytes(arr))
            }

            /// Default print.
            fn __repr__(&self, py: Python) -> PyResult<String> {
                match String::from_utf8(self.0.to_vec()) {
                    Ok(s) => match s.chars().all(is_printable_char) {
                        true => Ok(format!("{}(\"{}\")", $name, truncate(s, 20))),
                        false => Ok(format!("{}(#{})", $name, self.__hash__(py)?)),
                    },
                    Err(_) => Ok(format!("{}(#{})", $name, self.__hash__(py)?)),
                }
            }

            /// Makes the object hashable in Python.
            fn __hash__(&self, py: Python) -> PyResult<u64> {
                match PyBytes::new(py, &self.0).hash() {
                    Ok(val) => Ok(val as u64),
                    Err(e) => Err(e),
                }
            }

            fn is_equal(&self, other: Py<PyAny>, py: Python) -> PyResult<bool> {
                if let Ok(str) = other.extract::<&str>(py) {
                    Ok(self.0.as_ref() == str.as_bytes())
                } else if let Ok(bytes) = other.extract::<&[u8]>(py) {
                    Ok(self.0.as_ref() == bytes)
                } else if let Ok(int) = other.extract::<i64>(py) {
                    Ok(self.0.as_ref() == int.to_be_bytes())
                } else if let Ok(py_obj) = other.extract::<Self>(py) {
                    Ok(self.0 == py_obj.0)
                } else {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "Wrong type for comparison",
                    ));
                }
            }

            /// Implements comparison.
            fn __richcmp__(
                &self,
                other: Py<PyAny>,
                op: pyo3::basic::CompareOp,
                py: Python,
            ) -> PyResult<bool> {
                match op {
                    CompareOp::Eq => Ok(self.is_equal(other, py)?),
                    CompareOp::Ne => Ok(!self.is_equal(other, py)?),
                    _ => Err(pyo3::exceptions::PyNotImplementedError::new_err(
                        "Comparison operator not available",
                    )),
                }
            }
        }
    };
}
