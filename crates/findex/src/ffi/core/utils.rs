use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    ffi::c_uchar,
    fmt::Display,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use cosmian_crypto_core::symmetric_crypto::Dem;
use cosmian_findex::{
    parameters::{DemScheme, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KWI_LENGTH, UID_LENGTH},
    IndexedValue, Keyword,
};

use super::callbacks::FetchEntryTableCallback;
use crate::ffi::{ErrorCode, FindexFfiError};

/// Makes sure the given callback exists in the given Findex instance.
///
/// - `findex`      : name of the findex instance
/// - `callback`    : name of the callback
macro_rules! unwrap_callback {
    ($callback_name:literal, $findex:ident, $callback:ident) => {
        $findex
            .$callback
            .as_ref()
            .ok_or_else(|| FindexFfiError::CallbackNotImplemented {
                callback_name: $callback_name,
            })?
    };
}

/// Maximum number of bytes used by a LEB128 encoding.
///
/// `8` LEB128 bytes can encode numbers up to `2^56` which should be an upper
/// bound on the number of table lines
const LEB128_MAXIMUM_ENCODED_BYTES_NUMBER: usize = 8;

/// Returns an upper-bound on the size of a serialized encrypted Entry Table.
///
/// An Entry Table line is composed of:
/// - the Entry Table UID;
/// - the `Kwi`;
/// - the Chain Table UID;
/// - the `Keyword` hash.
///
/// Therefore the serialized encrypted Entry Table looks like:
///
/// `| LEB128(table.len()) | UID1 | encrypted_value1 | ...`
///
/// where the size of an encrypted value is:
///
/// `ENCRYPTION_OVERHEAD + KWI_LENGTH + UID_LENGTH + KEYWORD_HASH_LENGTH`
///
/// # Arguments
/// - `line_number` : number of lines in the encrypted Entry Table
/// - `entry_table_number` : number of different entry tables. The number is
///   required here since severable entry table could give multiple results
pub const fn get_serialized_encrypted_entry_table_size_bound(
    line_number: usize,
    entry_table_number: usize,
) -> usize {
    LEB128_MAXIMUM_ENCODED_BYTES_NUMBER
        + line_number
            * entry_table_number
            * (UID_LENGTH
                + DemScheme::ENCRYPTION_OVERHEAD
                + KWI_LENGTH
                + UID_LENGTH
                + Keyword::HASH_LENGTH)
}

/// Returns an upper-bound on the size of a serialized encrypted Chain Table.
///
/// A Chain Table line is composed of:
/// - the Chain Table UID;
/// - `CHAIN_TABLE_WIDTH` blocks of length `BLOCK_LENGTH`
///
/// Therefore the serialized encrypted Entry Table looks like:
///
/// `| LEB128(table.len()) | UID1 | encrypted_value1 | ...`
///
/// where the size of an encrypted value is:
///
/// `ENCRYPTION_OVERHEAD + 1 + CHAIN_TABLE_WIDTH * (1 + BLOCK_LENGTH)`
///
/// # Arguments
/// - `line_number` : number of lines in the encrypted Entry Table
pub const fn get_allocation_size_for_select_chain_request(line_number: usize) -> usize {
    LEB128_MAXIMUM_ENCODED_BYTES_NUMBER
        + line_number
            * (UID_LENGTH
                + DemScheme::ENCRYPTION_OVERHEAD
                + 1
                + CHAIN_TABLE_WIDTH * (1 + BLOCK_LENGTH))
}

/// Call the given fetch callback.
///
/// - `uids`            : UIDs to fetch (callback input)
/// - `allocation_size` : size needed to be allocated for the output
/// - `callback`        : fetch callback
pub(crate) fn fetch_callback(
    uids: &[u8],
    allocation_size: usize,
    callback: FetchEntryTableCallback,
    debug_name: &'static str,
) -> Result<Vec<u8>, FindexFfiError> {
    //
    // DB request with correct allocation size
    //
    let mut output_bytes = vec![0_u8; allocation_size];
    let mut output_ptr = output_bytes.as_mut_ptr().cast::<c_uchar>();
    let mut output_len = u32::try_from(allocation_size)?;

    let mut error_code = callback(
        output_ptr,
        &mut output_len,
        uids.as_ptr(),
        u32::try_from(uids.len())?,
    );

    if error_code == ErrorCode::BufferTooSmall.code() {
        output_bytes = vec![0_u8; output_len as usize];
        output_ptr = output_bytes.as_mut_ptr().cast::<c_uchar>();

        error_code = callback(
            output_ptr,
            &mut output_len,
            uids.as_ptr(),
            u32::try_from(uids.len())?,
        );
    }

    if error_code != ErrorCode::Success.code() {
        return Err(FindexFfiError::UserCallbackErrorCode {
            callback_name: debug_name,
            code: error_code,
        });
    }

    if output_len == 0 {
        return Ok(vec![]);
    }

    //
    // Recopy buffer in Vec<u8>
    //
    let output_entries_bytes = unsafe {
        std::slice::from_raw_parts(output_ptr as *const u8, output_len as usize).to_vec()
    };
    Ok(output_entries_bytes)
}

pub(crate) fn parse_indexed_values(
    serialized_values: &str,
) -> Result<HashMap<IndexedValue, HashSet<Keyword>>, ParseIndexedValuesError> {
    // Indexed values and keywords are a map of base64 encoded `IndexedValue` to a
    // list of base64 encoded keywords. Why that? We should use simple
    // serialization to pass the data and not depend on JSON+base64 to improve
    // performances.
    // <https://github.com/Cosmian/findex/issues/19>
    let additions_base64: HashMap<String, Vec<String>> =
        serde_json::from_str(serialized_values).map_err(ParseIndexedValuesError::Json)?;

    let mut additions = HashMap::with_capacity(additions_base64.len());
    for (indexed_value, keywords_vec) in additions_base64 {
        let indexed_value_bytes = STANDARD
            .decode(indexed_value)
            .map_err(ParseIndexedValuesError::Base64Decode)?;
        let indexed_value = IndexedValue::try_from(indexed_value_bytes.as_slice())
            .map_err(|e| ParseIndexedValuesError::Decoding(e.to_string()))?;
        let mut keywords = HashSet::with_capacity(keywords_vec.len());
        for keyword in keywords_vec {
            let keyword_bytes = STANDARD
                .decode(keyword)
                .map_err(ParseIndexedValuesError::Base64Decode)?;
            keywords.insert(Keyword::from(keyword_bytes));
        }
        additions.insert(indexed_value, keywords);
    }

    Ok(additions)
}

pub(crate) enum ParseIndexedValuesError {
    Json(serde_json::Error),
    Base64Decode(base64::DecodeError),
    Decoding(String),
}

impl Display for ParseIndexedValuesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "json error {e}"),
            Self::Base64Decode(e) => write!(f, "base64 error {e}"),
            Self::Decoding(e) => write!(f, "bytes error {e}"),
        }
    }
}
