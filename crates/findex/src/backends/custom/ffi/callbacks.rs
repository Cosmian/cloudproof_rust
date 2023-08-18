//! Defines the FFI types for the callbacks used in Findex.

use cosmian_findex::{
    EncryptedValue, Token, TokenToEncryptedValueMap, TokenWithEncryptedValueList, Tokens,
};

use crate::{backends::BackendError, ser_de::ffi_ser_de::*, ErrorCode};

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

pub const fn get_serialized_edx_lines_size_bound<const VALUE_LENGTH: usize>(
    n_lines: usize,
    n_tables: usize,
) -> usize {
    MAX_LEB128_ENCODING_SIZE
        + n_lines * n_tables * (Token::LENGTH + EncryptedValue::<VALUE_LENGTH>::LENGTH)
}

impl FfiCallbacks {
    pub(crate) async fn fetch<const LENGTH: usize>(
        &self,
        uids: Tokens,
    ) -> Result<TokenWithEncryptedValueList<LENGTH>, BackendError> {
        if let Some(fetch) = &self.fetch {
            let allocation_size =
                get_serialized_edx_lines_size_bound::<LENGTH>(uids.len(), self.table_number);

            let mut output_bytes = vec![0_u8; allocation_size];
            let output_ptr = output_bytes.as_mut_ptr().cast();
            let mut output_len = u32::try_from(allocation_size)?;

            let serialized_uids = serialize_token_set(&uids)?;

            let err = (fetch)(
                output_ptr,
                &mut output_len,
                serialized_uids.as_ptr(),
                serialized_uids.len() as u32,
            );

            if err == ErrorCode::Success.code() {
                let res = unsafe {
                    std::slice::from_raw_parts(output_ptr.cast_const(), output_len as usize)
                        .to_vec()
                };

                deserialize_edx_lines(&res)
                    .map_err(BackendError::from)
                    .map(Into::into)
            } else {
                Err(BackendError::Ffi("$name fetch".to_string(), err))
            }
        } else {
            Err(BackendError::MissingCallback(
                "no fetch callback found".to_string(),
            ))
        }
    }

    pub(crate) async fn upsert<const LENGTH: usize>(
        &self,
        old_values: TokenToEncryptedValueMap<LENGTH>,
        new_values: TokenToEncryptedValueMap<LENGTH>,
    ) -> Result<TokenToEncryptedValueMap<LENGTH>, BackendError> {
        if let Some(upsert) = &self.upsert {
            let allocation_size =
                new_values.len() * (Token::LENGTH + EncryptedValue::<LENGTH>::LENGTH);

            let mut output_bytes = vec![0_u8; allocation_size];
            let output_ptr = output_bytes.as_mut_ptr().cast();
            let mut output_len = u32::try_from(allocation_size)?;

            let serialized_old_values = serialize_edx_lines(&old_values.into())?;
            let serialized_new_values = serialize_edx_lines(&new_values.into())?;
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

            if err == ErrorCode::Success.code() {
                let res = unsafe {
                    std::slice::from_raw_parts(output_ptr.cast_const(), output_len as usize)
                        .to_vec()
                };
                Ok(deserialize_edx_lines(&res)?.into_iter().collect())
            } else {
                Err(BackendError::Ffi("$name upsert error".to_string(), err))
            }
        } else {
            Err(BackendError::MissingCallback(
                "no fetch callback found".to_string(),
            ))
        }
    }

    pub(crate) async fn insert<const LENGTH: usize>(
        &self,
        map: TokenToEncryptedValueMap<LENGTH>,
    ) -> Result<(), BackendError> {
        if let Some(insert) = &self.insert {
            let serialized_map = serialize_edx_lines(&map)?;
            let serialized_map_len = <u32>::try_from(serialized_map.len())?;

            let err = (insert)(serialized_map.as_ptr(), serialized_map_len);

            if err == ErrorCode::Success.code() {
                Ok(())
            } else {
                Err(BackendError::Ffi("$name insert".to_string(), err))
            }
        } else {
            Err(BackendError::MissingCallback(
                "no insert callback found".to_string(),
            ))
        }
    }

    pub(crate) async fn delete(&self, uids: Tokens) -> Result<(), BackendError> {
        if let Some(delete) = &self.delete {
            let serialized_uids = serialize_token_set(&uids)?;
            let serialized_uids_len = <u32>::try_from(serialized_uids.len())?;
            let err = (delete)(serialized_uids.as_ptr(), serialized_uids_len);
            if err != ErrorCode::Success.code() {
                return Err(BackendError::Ffi("$name delete".to_string(), err));
            }
            Ok(())
        } else {
            Err(BackendError::MissingCallback(
                "no fetch callback found".to_string(),
            ))
        }
    }

    pub(crate) async fn dump_tokens(&self) -> Result<Tokens, BackendError> {
        if let Some(dump_tokens) = &self.dump_tokens {
            let mut allocation_size = 1_000_000 * Token::LENGTH;
            let mut is_first_try = true;

            loop {
                let mut output_bytes = vec![0_u8; allocation_size];
                let output_ptr = output_bytes.as_mut_ptr().cast::<u8>();
                let mut output_len = u32::try_from(allocation_size)?;

                let err = (dump_tokens)(output_ptr, &mut output_len);

                if err == ErrorCode::Success.code() {
                    let uids_bytes = unsafe {
                        std::slice::from_raw_parts(output_ptr.cast_const(), output_len as usize)
                    };
                    return deserialize_token_set(uids_bytes)
                        .map_err(BackendError::from)
                        .map(Into::into);
                } else if is_first_try && err == ErrorCode::BufferTooSmall.code() {
                    allocation_size = output_len as usize;
                    is_first_try = false;
                } else {
                    return Err(BackendError::Ffi("$name token dump".to_string(), err));
                }
            }
        } else {
            Err(BackendError::MissingCallback(
                "no fetch callback found".to_string(),
            ))
        }
    }
}
