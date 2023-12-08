pub use std::ffi::CStr;

/// Asserts a pointer is not `null`.
///
/// Sets the given message as last error and returns early with 1.
///
/// - `name`    : name of the object to use in error message
/// - `ptr`     : pointer to check
#[macro_export]
macro_rules! ffi_not_null {
    ($name:literal, $ptr:expr) => {
        if $ptr.is_null() {
            $crate::error::set_last_error($crate::error::FfiError::NullPointer($name.to_string()));
            return -1_i32;
        }
    };
    ($name:literal, $ptr:expr, $code:expr) => {
        if $ptr.is_null() {
            $crate::error::set_last_error($crate::error::FfiError::NullPointer($name.to_string()));
            return $code;
        }
    };
}

/// Unwraps an `std::result::Result`.
///
/// If the result is an error, sets the last error to this error and returns
/// early with -1 or the given error code.
///
/// - `res` : result to unwrap
/// - `msg` : additional message to use as error
#[macro_export]
macro_rules! ffi_unwrap {
    ($res:expr, $msg:expr, $code:expr) => {
        match $res {
            Ok(v) => v,
            Err(e) => {
                $crate::error::set_last_error($crate::error::FfiError::Generic(format!(
                    "{}: {}",
                    $msg, e
                )));
                return $code.into();
            }
        }
    };
}

/// Returns with an error.
///
/// Sets the last error to the given message and returns early with the given
/// error code if given or 1 if it's not.
///
/// - `msg` : error message to set
/// - `err` : (optional) error code to return
#[macro_export]
macro_rules! ffi_bail {
    ($msg:literal $(,)?) => {
        $crate::error::set_last_error($crate::error::FfiError::Generic($msg.to_owned()));
        return -1_i32;
    };
    ($err:expr $(,)?) => {
        $crate::error::set_last_error($crate::error::FfiError::Generic($err.to_string()));
        return -1_i32;
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::set_last_error($crate::error::FfiError::Generic(format!($fmt, $($arg)*)));
        return -1_i32;
    };
}

/// Writes the given bytes to FFI buffers with checks.
///
/// # Description
///
/// For each buffer, `$ptr` should contain a valid pointer to this buffer and
/// `$len` should contain the correct size allocated to this buffer.
///
/// # Error
///
/// The pointers to each buffer should not be null and enough space should be
/// allocated. The number of failed write operation is returned. Upon return,
/// the correct number of bytes to allocate to each buffer is written in the
/// associated `$len` variable.
///
/// The last error can be retrieved using `h_get_error` (via FFI) or
/// `get_last_error` (via Rust).
///
/// # Safety
///
/// If the allocated space is fewer than `$len`, calling this macro may result
/// in a runtime memory error.
///
/// # Parameters
///
/// - `name`    : object name to use in error message
/// - `bytes`   : bytes to write
/// - `ptr`     : pointer to the output buffer
/// - `len`     : length of the output buffer
#[macro_export]
macro_rules! ffi_write_bytes {
    ($($name: literal, $bytes: expr, $ptr: ident, $len: ident $(,)?)+) => {

        let mut error_code = 0_i32;
        let mut nul_error = false;

        // Write outputs one by one. Do not return on error
        $(
            if $ptr.is_null() {
                $crate::error::set_last_error($crate::error::FfiError::NullPointer($name.to_string()));
                nul_error = true;
            } else {
                let allocated = *$len;
                *$len = $bytes.len() as i32;
                if allocated < *$len {
                    $crate::error::set_last_error($crate::error::FfiError::Generic(format!(
                        "The pre-allocated {} buffer is too small; need {} bytes, allocated {allocated}",
                        $name, *$len
                    )));
                    error_code = 1_i32;
                } else {
                    std::slice::from_raw_parts_mut($ptr.cast(), $bytes.len()).copy_from_slice($bytes);
                }
            }

        )+;

        if nul_error {
            return -1_i32;
        }else {
            return error_code;
        }
    };
}

/// Reads bytes from an FFI pointer with checks.
///
/// # Description
///
/// Reads `$len` bytes from `$ptr` if it is a valid pointer.
///
/// # Error
///
/// The pointer should not be null and its length should be greater than 0. An
/// error code of 1 is return if one of the previous conditions is not true.
///
/// # Safety
///
/// Passing a `$len` greater than the actual buffer length will result in a
/// buffer overflow.
///
/// # Parameters
///
/// - `name`    : object name to use in error message
/// - `ptr`     : pointer to the input buffer
/// - `len`     : length of the input buffer
#[macro_export]
macro_rules! ffi_read_bytes {
    ($name:literal, $ptr:ident, $len:ident) => {{
        $crate::ffi_not_null!($name, $ptr);

        if $len == 0 {
            $crate::ffi_bail!(format!(
                "{} buffer should have a size greater than zero",
                $name
            ));
        }

        std::slice::from_raw_parts($ptr.cast(), $len as usize)
    }};
}

/// Reads a Rust string from the given pointer to a null-terminated C string.
///
/// Asserts the given pointer is not null and reads a null-terminated C
/// string from it. Converts it into Rust string.
///
/// - `name`    : object name to use in error message
/// - `ptr`     : pointer to the input null-terminated C string
#[macro_export]
macro_rules! ffi_read_string {
    ($name:literal, $ptr:ident) => {{
        $crate::ffi_not_null!($name, $ptr);

        match $crate::macros::CStr::from_ptr($ptr.cast::<std::ffi::c_char>()).to_str() {
            Ok(msg) => msg.to_owned(),
            Err(e) => {
                $crate::ffi_bail!(format!("{} invalid C string: {}", $name, e));
            }
        }
    }};
}
