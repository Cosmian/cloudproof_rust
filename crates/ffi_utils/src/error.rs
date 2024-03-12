use core::{cell::RefCell, fmt::Display};
use std::ffi::CString;

use crate::ErrorCode;

#[derive(Debug)]
pub enum FfiError {
    NullPointer(String),
    Generic(String),
}

impl Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NullPointer(pointer_name) => write!(f, "{pointer_name} shouldn't be null"),
            Self::Generic(err) => write!(f, "{err}"),
        }
    }
}

thread_local! {
    /// a thread-local variable which holds the most recent error
    static LAST_ERROR: RefCell<Option<Box<FfiError>>> = const { RefCell::new(None) };
}

/// Sets the most recent error, clearing whatever may have been there before.
///
/// - `err` : error to set
#[inline]
pub fn set_last_error(err: FfiError) {
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(Box::new(err));
    });
}

/// Gets the last error message.
#[inline]
#[must_use]
pub fn get_last_error() -> String {
    LAST_ERROR
        .with(|prev| prev.borrow_mut().take())
        .map_or(String::new(), |e| e.to_string())
}

/// Externally sets the last error recorded on the Rust side.
///
/// # Safety
///
/// The pointer must point to a null-terminated string.
///
/// This function is meant to be called from the Foreign Function
/// Interface.
///
/// # Parameters
///
/// - `error_message_ptr`   : pointer to the error message to set
#[no_mangle]
pub unsafe extern "C" fn h_set_error(error_message_ptr: *const i8) -> i32 {
    let error_message = ffi_read_string!("error message", error_message_ptr);
    set_last_error(FfiError::Generic(error_message));
    0
}

/// Externally gets the most recent error recorded on the Rust side, clearing
/// it in the process.
///
/// # Safety
///
/// The pointer `error_ptr` should point to a buffer which has been allocated
/// `error_len` bytes. If the allocated size is smaller than `error_len`, a
/// call to this function may result in a buffer overflow.
///
/// # Parameters
///
/// - `error_ptr`: pointer to the buffer to which to write the error
/// - `error_len`: size of the allocated memory
#[no_mangle]
pub unsafe extern "C" fn h_get_error(error_ptr: *mut i8, error_len: *mut i32) -> i32 {
    // Get the error message as a null terminated string.
    let cs = ffi_unwrap!(
        CString::new(get_last_error()),
        "failed to convert error to CString",
        ErrorCode::InvalidArgument("CString".to_string())
    );

    ffi_write_bytes!("error", cs.as_bytes(), error_ptr, error_len);
}

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;

    use super::*;

    #[test]
    fn test_error() {
        let error_msg = "Emergency!!!";

        // Set the error message.
        let res = unsafe { h_set_error(error_msg.as_ptr().cast::<i8>()) };
        assert_eq!(res, 0);

        // Reads the error message.
        let res = unsafe {
            let mut bytes = [0u8; 8192];
            let ptr = bytes.as_mut_ptr().cast();
            let mut len = bytes.len() as i32;
            h_get_error(ptr, &mut len);
            String::from_utf8(bytes[..len as usize].to_vec()).unwrap()
        };
        assert!(res.contains(error_msg));

        // Reads the error message.
        unsafe {
            let ptr = null_mut::<u8>();
            let mut len = 10;
            h_get_error(ptr.cast(), &mut len);
        };

        // Reads the error message.
        let res = unsafe {
            let mut bytes = [0u8; 8192];
            let ptr = bytes.as_mut_ptr().cast();
            let mut len = bytes.len() as i32;
            h_get_error(ptr, &mut len);
            String::from_utf8(bytes[..len as usize].to_vec()).unwrap()
        };
        assert!(res.contains("shouldn't be null"));
    }
}
