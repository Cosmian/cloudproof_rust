//! Defines the FFI types for the callbacks used in Findex.

use cosmian_ffi_utils::ErrorCode;
use cosmian_findex::{Token, TokenToEncryptedValueMap, Tokens};
use tracing::{debug, instrument, trace};

use crate::{
    db_interfaces::DbInterfaceError,
    ser_de::ffi_ser_de::{
        deserialize_edx_lines, deserialize_token_set, get_serialized_edx_lines_size_bound,
        serialize_edx_lines, serialize_token_set,
    },
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
#[derive(Clone, Debug)]
pub struct FfiCallbacks {
    pub table_number: usize,
    pub fetch: Option<Fetch>,
    pub upsert: Option<Upsert>,
    pub insert: Option<Insert>,
    pub delete: Option<Delete>,
    pub dump_tokens: Option<DumpTokens>,
}

impl FfiCallbacks {
    #[instrument(ret(Display), err, skip_all)]
    pub(crate) async fn fetch<const LENGTH: usize>(
        &self,
        tokens: cosmian_findex::Tokens,
    ) -> Result<cosmian_findex::TokenWithEncryptedValueList<LENGTH>, DbInterfaceError> {
        trace!("fetch: entering: tokens: {tokens}");
        debug!(
            "fetch: entering: tokens number: {}, table_number: {}",
            tokens.len(),
            self.table_number
        );

        let fetch = self.fetch.as_ref().ok_or_else(|| {
            DbInterfaceError::MissingCallback("no fetch callback found".to_string())
        })?;

        let allocation_size =
            get_serialized_edx_lines_size_bound::<LENGTH>(tokens.len(), self.table_number);
        trace!("fetch: output allocation_size: {}", allocation_size);

        let mut output_bytes = vec![0_u8; allocation_size];
        let output_ptr = output_bytes.as_mut_ptr().cast();
        let mut output_len = u32::try_from(allocation_size)?;

        let serialized_tokens = serialize_token_set(&tokens)?;
        let serialized_tokens_len = u32::try_from(serialized_tokens.len())?;

        trace!(
            "fetch: serialized_tokens length: {}",
            serialized_tokens.len()
        );

        let err = (fetch)(
            output_ptr,
            &mut output_len,
            serialized_tokens.as_ptr(),
            serialized_tokens_len,
        );

        if err == 0 {
            let res = unsafe {
                std::slice::from_raw_parts(output_ptr.cast_const(), output_len as usize).to_vec()
            };

            let token_encrypted_value_list =
                deserialize_edx_lines(&res).map_err(DbInterfaceError::from)?;
            debug!(
                "fetch: exiting successfully with {} values",
                token_encrypted_value_list.len()
            );
            Ok(token_encrypted_value_list)
        } else {
            Err(DbInterfaceError::Ffi("fetch error".to_string(), err.into()))
        }
    }

    #[instrument(ret(Display), err, skip_all)]
    pub(crate) async fn upsert<const LENGTH: usize>(
        &self,
        old_values: cosmian_findex::TokenToEncryptedValueMap<LENGTH>,
        new_values: cosmian_findex::TokenToEncryptedValueMap<LENGTH>,
    ) -> Result<cosmian_findex::TokenToEncryptedValueMap<LENGTH>, DbInterfaceError> {
        trace!("upsert: entering: old_values: {old_values}");
        trace!("upsert: entering: new_values: {new_values}");
        debug!(
            "upsert: entering: old_values size: {} new_values size: {}",
            old_values.len(),
            new_values.len()
        );

        let upsert = self.upsert.as_ref().ok_or_else(|| {
            DbInterfaceError::MissingCallback("no upsert callback found".to_string())
        })?;

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

        if err == 0 {
            let res = unsafe {
                std::slice::from_raw_parts(output_ptr.cast_const(), output_len as usize).to_vec()
            };
            let token_encrypted_value_map: cosmian_findex::TokenToEncryptedValueMap<LENGTH> =
                deserialize_edx_lines(&res)?.into_iter().collect();
            debug!(
                "upsert: exiting successfully with {} values",
                token_encrypted_value_map.len()
            );
            Ok(token_encrypted_value_map)
        } else {
            Err(DbInterfaceError::Ffi(
                "upsert error".to_string(),
                err.into(),
            ))
        }
    }

    #[instrument(err, skip_all)]
    pub(crate) async fn insert<const LENGTH: usize>(
        &self,
        map: TokenToEncryptedValueMap<LENGTH>,
    ) -> Result<(), DbInterfaceError> {
        trace!("insert: entering: map: {map}");
        debug!("insert: entering: map size: {}", map.len());

        let insert = self.insert.as_ref().ok_or_else(|| {
            DbInterfaceError::MissingCallback("no insert callback found".to_string())
        })?;

        let serialized_map = serialize_edx_lines(&map)?;
        let serialized_map_len = <u32>::try_from(serialized_map.len())?;

        let err = (insert)(serialized_map.as_ptr(), serialized_map_len).into();

        if ErrorCode::Success == err {
            tracing::debug!(
                "insert: exiting successfully: number inserted {}",
                map.len()
            );
            Ok(())
        } else {
            Err(DbInterfaceError::Ffi("insert error".to_string(), err))
        }
    }

    #[instrument(err, skip_all)]
    pub(crate) async fn delete(&self, tokens: Tokens) -> Result<(), DbInterfaceError> {
        trace!("delete: entering: tokens: {tokens}");
        debug!("delete: entering: tokens number {}", tokens.len());
        let delete = self.delete.as_ref().ok_or_else(|| {
            DbInterfaceError::MissingCallback("no delete callback found".to_string())
        })?;

        let serialized_uids = serialize_token_set(&tokens)?;
        let serialized_uids_len = <u32>::try_from(serialized_uids.len())?;

        let err = (delete)(serialized_uids.as_ptr(), serialized_uids_len).into();

        if ErrorCode::Success == err {
            tracing::debug!(
                "delete: exiting successfully: token number deleted {}",
                tokens.len()
            );
            Ok(())
        } else {
            Err(DbInterfaceError::Ffi("delete error".to_string(), err))
        }
    }

    #[instrument(ret(Display), err, skip_all)]
    pub(crate) async fn dump_tokens(&self) -> Result<Tokens, DbInterfaceError> {
        debug!("dump_tokens: entering");

        let dump_tokens = self.dump_tokens.as_ref().ok_or_else(|| {
            DbInterfaceError::MissingCallback("no dump_tokens callback found".to_string())
        })?;

        let mut allocation_size = 1_000_000 * Token::LENGTH;
        let mut output_bytes = vec![0_u8; allocation_size];
        let output_ptr = output_bytes.as_mut_ptr().cast::<u8>();
        let mut output_len = u32::try_from(allocation_size)?;

        let mut err = (dump_tokens)(output_ptr, &mut output_len).into();

        if ErrorCode::BufferTooSmall == err {
            // Second try in case not enough memory was allocated.
            // Use the length returned by the first function call.
            allocation_size = output_len as usize;
            let mut output_bytes = vec![0_u8; allocation_size];
            let output_ptr = output_bytes.as_mut_ptr().cast::<u8>();
            let mut output_len = u32::try_from(allocation_size)?;
            err = (dump_tokens)(output_ptr, &mut output_len).into();
        }

        if ErrorCode::Success == err {
            // TODO: why not directly use `output_bytes`?
            let tokens_bytes =
                unsafe { std::slice::from_raw_parts(output_ptr.cast_const(), output_len as usize) };
            let tokens = deserialize_token_set(tokens_bytes).map_err(DbInterfaceError::from)?;
            debug!("dump_tokens: exiting with {} tokens", tokens.len());
            Ok(tokens)
        } else {
            Err(DbInterfaceError::Ffi(
                "FfiCallbacks token dump".to_string(),
                err,
            ))
        }
    }
}
