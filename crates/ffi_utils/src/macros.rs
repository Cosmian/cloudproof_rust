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
            return 1_i32;
        }
    };
}

/// Unwraps an `std::result::Result`.
///
/// If the result is an error, sets the last error to this error and returns
/// early with 1.
///
/// - `res` : result to unwrap
/// - `msg` : (optional) additional message to use as error
#[macro_export]
macro_rules! ffi_unwrap {
    ($res:expr, $msg:literal) => {
        match $res {
            Ok(v) => v,
            Err(e) => {
                $crate::error::set_last_error($crate::error::FfiError::Generic(format!(
                    "{}: {}",
                    $msg, e
                )));
                return 1_i32;
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
    ($msg:expr) => {
        $crate::error::set_last_error($crate::error::FfiError::Generic($msg));
        return 1;
    };
    ($msg:expr, $err:expr) => {
        $crate::error::set_last_error($crate::error::FfiError::Generic($msg.to_string()));
        return $err;
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

        // Write outputs one by one. Do not return on error, increment the
        // `error_code` instead.
        $(
            if $ptr.is_null() {
                $crate::error::set_last_error($crate::error::FfiError::NullPointer($name.to_string()));
                error_code += 1;
            } else {
                let allocated = *$len;
                *$len = $bytes.len() as c_int;
                if allocated < *$len {
                    $crate::error::set_last_error($crate::error::FfiError::Generic(format!(
                        "The pre-allocated {} buffer is too small; need {} bytes, allocated {allocated}",
                        $name, *$len
                    )));
                    error_code += 1;
                } else {
                    std::slice::from_raw_parts_mut($ptr.cast(), $bytes.len()).copy_from_slice($bytes);
                }
            }

        )+;

        // Return here if there was an error. This allows for returning the
        // correct size for several output buffers at once. The number of
        // errors is returned.
        if error_code > 0 {
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

        match $crate::macros::CStr::from_ptr($ptr).to_str() {
            Ok(msg) => msg.to_owned(),
            Err(e) => {
                $crate::ffi_bail!(format!("{} invalid C string: {}", $name, e));
            }
        }
    }};
}
