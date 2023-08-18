//! Defines the FFI types for the callbacks used in Findex.

use cosmian_findex::{EncryptedValue, Token, TokenToEncryptedValueMap, Tokens};
use tracing::{debug, trace};

use crate::{
    backends::BackendError,
    ser_de::ffi_ser_de::{
        deserialize_edx_lines, deserialize_token_set, serialize_edx_lines, serialize_token_set,
    },
    ErrorCode,
};

/// # Serialization
///
/// Output: `LEB128(n_uids) || UID_1 || ... || UID_n`
pub type DumpTokens = extern "C" fn(uids_ptr: *mut u8, uids_len: *mut u32) -> i32;

/// # Serialization
///
/// Input:
/// `LEB128(n_uids) || UID_1 || ...`
///
/// Output:
/// `LEB128(n_entries) || UID_1 || LEB128(value_1.len()) || value_1 || ...`
pub type Fetch = extern "C" fn(
    output_ptr: *mut u8,
    output_len: *mut u32,
    uids_ptr: *const u8,
    uids_len: u32,
) -> i32;

/// # Serialization
///
/// Input:
/// `LEB128(n_values) || UID_1 || LEB128(value_1.len()) || value_1 || ...`
///
/// Output:
/// `LEB128(n_lines) || UID_1 || LEB128(value_1.len()) || value_1 || ...`
pub type Upsert = extern "C" fn(
    indexed_values_ptr: *mut u8,
    indexed_values_len: *mut u32,
    old_values_ptr: *const u8,
    old_values_len: u32,
    new_values_ptr: *const u8,
    new_values_len: u32,
) -> i32;

/// # Serialization
///
/// Input:
/// `LEB128(n_values) || UID_1 || LEB128(value_1.len() || value_1 || ...`
pub type Insert = extern "C" fn(input_ptr: *const u8, input_len: u32) -> i32;

/// # Serialization
///
/// Input:
/// `LEB128(n_values) || UID_1 || LEB128(value_1.len() || value_1 || ...`
pub type Delete = extern "C" fn(input_ptr: *const u8, input_len: u32) -> i32;

pub type Interrupt =
    extern "C" fn(intermediate_results_ptr: *const u8, intermediate_results_len: u32) -> i32;

pub type FilterObsoleteData = extern "C" fn(
    output_locations_ptr: *mut u8,
    output_locations_len: *mut u32,
    locations_ptr: *const u8,
    locations_len: u32,
) -> i32;

/// Structure storing the callback functions passed through the FFI. It also
/// stores the number of corresponding tables since to allow allocating the
/// correct amount of memory.
///
/// Callback functions needed to be implemented for the Entry and Chain tables
/// given the Findex operation:
/// ```txt
///           +-----------+-----------+-----------+-----------+---------------+
///           | `fetch`   | `upsert`  | `insert`  | `delete`  | `dump_tokens` |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// | search  |  ET + CT  |           |           |           |               |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// | add     |  ET + CT  |     ET    |    CT     |           |               |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// | delete  |  ET + CT  |     ET    |    CT     |           |               |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// | compact |  ET + CT  |           |  ET + CT  |  ET + CT  |       ET      |
/// +---------+-----------+-----------+-----------+-----------+---------------+
/// ```
#[derive(Debug)]
pub struct FfiCallbacks {
    pub table_number: usize,
    pub fetch: Option<Fetch>,
    pub upsert: Option<Upsert>,
    pub insert: Option<Insert>,
    pub delete: Option<Delete>,
    pub dump_tokens: Option<DumpTokens>,
}

/// Maximum number of bytes used by a LEB128 encoding.
///
/// `8` LEB128 bytes can encode numbers up to `2^56` which should be an upper
/// bound on the number of table lines
const MAX_LEB128_ENCODING_SIZE: usize = 8;

#[must_use]
pub const fn get_serialized_edx_lines_size_bound<const VALUE_LENGTH: usize>(
    n_lines: usize,
    n_tables: usize,
) -> usize {
    MAX_LEB128_ENCODING_SIZE
        + n_lines
            * n_tables
            * (Token::LENGTH + EncryptedValue::<VALUE_LENGTH>::LENGTH + MAX_LEB128_ENCODING_SIZE)
}

impl FfiCallbacks {
    #[tracing::instrument(level = "trace", fields(tokens = %tokens), ret(Display), err, skip(self))]
    pub(crate) async fn fetch<const LENGTH: usize>(
        &self,
        tokens: cosmian_findex::Tokens,
    ) -> Result<cosmian_findex::TokenWithEncryptedValueList<LENGTH>, BackendError> {
        debug!(
            "fetch: entering: tokens number: {}, table_number: {}",
            tokens.len(),
            self.table_number
        );
        if let Some(fetch) = &self.fetch {
            let allocation_size =
                get_serialized_edx_lines_size_bound::<LENGTH>(tokens.len(), self.table_number);
            trace!("fetch: output allocation_size: {}", allocation_size);

            let mut output_bytes = vec![0_u8; allocation_size];
            let output_ptr = output_bytes.as_mut_ptr().cast();
            let mut output_len = u32::try_from(allocation_size)?;

            let serialized_tokens = serialize_token_set(&tokens)?;
            trace!(
                "fetch: serialized_tokens length: {}",
                serialized_tokens.len()
            );
            let err = (fetch)(
                output_ptr,
                &mut output_len,
                serialized_tokens.as_ptr(),
                serialized_tokens.len() as u32,
            );

            match err {
                0 => {
                    let res = unsafe {
                        std::slice::from_raw_parts(output_ptr.cast_const(), output_len as usize)
                            .to_vec()
                    };

                    let token_encrypted_value_list =
                        deserialize_edx_lines(&res).map_err(BackendError::from)?;
                    debug!(
                        "fetch: exiting successfully with {} values",
                        token_encrypted_value_list.len()
                    );
                    Ok(token_encrypted_value_list)
                }
                1 => Err(BackendError::Ffi(
                    format!("'{}' buffer too small", "fetch"),
                    err,
                )),
                2 => Err(BackendError::Ffi(
                    format!("'{}' missing callback", "fetch"),
                    err,
                )),
                3 => Err(BackendError::Ffi(
                    format!("'{}' serialization error", "fetch"),
                    err,
                )),
                4 => Err(BackendError::Ffi(
                    format!("'{}' backend error", "fetch"),
                    err,
                )),
                _ => Err(BackendError::Ffi(
                    format!("'{}' other error: {err}", "fetch"),
                    err,
                )),
            }
        } else {
            Err(BackendError::MissingCallback(
                "no fetch callback found".to_string(),
            ))
        }
    }

    #[tracing::instrument(level = "trace", fields(old_values = %old_values, new_values = %new_values), ret(Display), err, skip(self))]
    pub(crate) async fn upsert<const LENGTH: usize>(
        &self,
        old_values: cosmian_findex::TokenToEncryptedValueMap<LENGTH>,
        new_values: cosmian_findex::TokenToEncryptedValueMap<LENGTH>,
    ) -> Result<cosmian_findex::TokenToEncryptedValueMap<LENGTH>, BackendError> {
        debug!(
            "upsert: entering: old_values size: {} new_values size: {}",
            old_values.len(),
            new_values.len()
        );
        if let Some(upsert) = &self.upsert {
            let allocation_size =
                get_serialized_edx_lines_size_bound::<LENGTH>(new_values.len(), self.table_number);

            let mut output_bytes = vec![0_u8; allocation_size];
            let output_ptr = output_bytes.as_mut_ptr().cast();
            let mut output_len = u32::try_from(allocation_size)?;

            let serialized_old_values = serialize_edx_lines(&old_values)?;
            let serialized_new_values = serialize_edx_lines(&new_values)?;
            let serialized_old_values_len = <u32>::try_from(serialized_old_values.len())?;
            let serialized_new_values_len = <u32>::try_from(serialized_new_values.len())?;

            let err = (upsert)(
                output_ptr,
                &mut output_len,
                serialized_old_values.as_ptr(),
                serialized_old_values_len,
                serialized_new_values.as_ptr(),
                serialized_new_values_len,
            );

            match err {
                0 => {
                    let res = unsafe {
                        std::slice::from_raw_parts(output_ptr.cast_const(), output_len as usize)
                            .to_vec()
                    };
                    let token_encrypted_value_map: cosmian_findex::TokenToEncryptedValueMap<
                        LENGTH,
                    > = deserialize_edx_lines(&res)?.into_iter().collect();
                    debug!(
                        "upsert: exiting successfully with {} values",
                        token_encrypted_value_map.len()
                    );
                    Ok(token_encrypted_value_map)
                }
                1 => Err(BackendError::Ffi(
                    format!("'{}' buffer too small", "upsert"),
                    err,
                )),
                2 => Err(BackendError::Ffi(
                    format!("'{}' missing callback", "upsert"),
                    err,
                )),
                3 => Err(BackendError::Ffi(
                    format!("'{}' serialization error", "upsert"),
                    err,
                )),
                4 => Err(BackendError::Ffi(
                    format!("'{}' backend error", "upsert"),
                    err,
                )),
                _ => Err(BackendError::Ffi(
                    format!("'{}' other error: {err}", "upsert"),
                    err,
                )),
            }
        } else {
            Err(BackendError::MissingCallback(
                "no upsert callback found".to_string(),
            ))
        }
    }

    pub(crate) async fn insert<const LENGTH: usize>(
        &self,
        map: TokenToEncryptedValueMap<LENGTH>,
    ) -> Result<(), BackendError> {
        tracing::debug!("insert: entering: map size: {}", map.len());
        if let Some(insert) = &self.insert {
            let serialized_map = serialize_edx_lines(&map)?;
            let serialized_map_len = <u32>::try_from(serialized_map.len())?;

            let err = (insert)(serialized_map.as_ptr(), serialized_map_len);

            if err == ErrorCode::Success.code() {
                tracing::debug!(
                    "insert: exiting successfully: number inserted {}",
                    map.len()
                );
                Ok(())
            } else {
                Err(BackendError::Ffi("FfiCallbacks insert".to_string(), err))
            }
        } else {
            Err(BackendError::MissingCallback(
                "no insert callback found".to_string(),
            ))
        }
    }

    pub(crate) async fn delete(&self, tokens: Tokens) -> Result<(), BackendError> {
        tracing::debug!("delete: entering: tokens number {}", tokens.len());
        if let Some(delete) = &self.delete {
            let serialized_uids = serialize_token_set(&tokens)?;
            let serialized_uids_len = <u32>::try_from(serialized_uids.len())?;
            let err = (delete)(serialized_uids.as_ptr(), serialized_uids_len);
            if err != ErrorCode::Success.code() {
                return Err(BackendError::Ffi("FfiCallbacks delete".to_string(), err));
            }

            tracing::debug!(
                "delete: exiting successfully: token number deleted {}",
                tokens.len()
            );
            Ok(())
        } else {
            Err(BackendError::MissingCallback(
                "no delete callback found".to_string(),
            ))
        }
    }

    pub(crate) async fn dump_tokens(&self) -> Result<Tokens, BackendError> {
        debug!("dump_tokens: entering");
        if let Some(dump_tokens) = &self.dump_tokens {
            let mut allocation_size = 1_000_000 * Token::LENGTH;
            let mut is_first_try = true;

            loop {
                let mut output_bytes = vec![0_u8; allocation_size];
                let output_ptr = output_bytes.as_mut_ptr().cast::<u8>();
                let mut output_len = u32::try_from(allocation_size)?;

                let err = (dump_tokens)(output_ptr, &mut output_len);

                if err == ErrorCode::Success.code() {
                    let tokens_bytes = unsafe {
                        std::slice::from_raw_parts(output_ptr.cast_const(), output_len as usize)
                    };
                    let tokens = deserialize_token_set(tokens_bytes).map_err(BackendError::from)?;
                    debug!("dump_tokens: exiting with {} tokens", tokens.len());
                    return Ok(tokens);
                } else if is_first_try && err == ErrorCode::BufferTooSmall.code() {
                    allocation_size = output_len as usize;
                    is_first_try = false;
                } else {
                    return Err(BackendError::Ffi(
                        "FfiCallbacks token dump".to_string(),
                        err,
                    ));
                }
            }
        } else {
            Err(BackendError::MissingCallback(
                "no dump_tokens callback found".to_string(),
            ))
        }
    }
}
