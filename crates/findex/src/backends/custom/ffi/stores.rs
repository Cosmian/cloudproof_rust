use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
};

use async_trait::async_trait;
use cosmian_findex::{EdxStore, EncryptedValue, ENTRY_LENGTH, LINK_LENGTH, TOKEN_LENGTH};

use super::MAX_LEB128_ENCODING_SIZE;
use crate::{
    backends::{ffi::callbacks::*, BackendError},
    ser_de::ffi_ser_de::*,
    ErrorCode, Uid,
};

/// Implements `EdxStore` for the given `$type`, with values of size
/// `$value_length`.
macro_rules! impl_ffi_edx_store {
    ($type:ident, $value_length:ident, $name:literal) => {
        impl $type {
            pub fn new(callbacks: FfiBackend) -> Self {
                Self(callbacks)
            }
        }

        impl Deref for $type {
            type Target = FfiBackend;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        #[async_trait(?Send)]
        impl EdxStore<$value_length> for $type {
            type Error = BackendError;
            type Token = Uid;

            async fn dump_tokens(&self) -> Result<HashSet<Self::Token>, Self::Error> {
                let mut allocation_size = 1_000_000 * TOKEN_LENGTH;
                let mut is_first_try = true;

                loop {
                    let mut output_bytes = vec![0_u8; allocation_size];
                    let output_ptr = output_bytes.as_mut_ptr().cast::<u8>();
                    let mut output_len = u32::try_from(allocation_size)?;

                    let err = (self.get_dump_token()?)(output_ptr, &mut output_len);

                    if err == ErrorCode::Success.code() {
                        let uids_bytes = unsafe {
                            std::slice::from_raw_parts(output_ptr.cast_const(), output_len as usize)
                        };
                        return deserialize_uid_set(uids_bytes).map_err(Self::Error::from);
                    } else if is_first_try && err == ErrorCode::BufferTooSmall.code() {
                        allocation_size = output_len as usize;
                        is_first_try = false;
                    } else {
                        return Err(Self::Error::Ffi("$name token dump".to_string(), err));
                    }
                }
            }

            async fn fetch(
                &self,
                uids: std::collections::HashSet<Self::Token>,
            ) -> Result<Vec<(Self::Token, EncryptedValue<$value_length>)>, Self::Error> {
                let allocation_size = get_serialized_edx_lines_size_bound::<$value_length>(
                    uids.len(),
                    self.table_number,
                );

                let mut output_bytes = vec![0_u8; allocation_size];
                let output_ptr = output_bytes.as_mut_ptr().cast();
                let mut output_len = u32::try_from(allocation_size)?;

                let serialized_uids = serialize_uid_set(&uids)?;

                let err = (self.get_fetch()?)(
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

                    deserialize_edx_lines(&res).map_err(Self::Error::from)
                } else {
                    Err(Self::Error::Ffi("$name fetch".to_string(), err))
                }
            }

            async fn upsert(
                &self,
                old_values: &HashMap<Self::Token, EncryptedValue<$value_length>>,
                new_values: HashMap<Self::Token, EncryptedValue<$value_length>>,
            ) -> Result<HashMap<Self::Token, EncryptedValue<$value_length>>, Self::Error> {
                let allocation_size =
                    new_values.len() * (TOKEN_LENGTH + EncryptedValue::<$value_length>::LENGTH);

                let mut output_bytes = vec![0_u8; allocation_size];
                let output_ptr = output_bytes.as_mut_ptr().cast();
                let mut output_len = u32::try_from(allocation_size)?;

                let serialized_old_values = serialize_edx_lines(old_values)?;
                let serialized_new_values = serialize_edx_lines(&new_values)?;
                let serialized_old_values_len = <u32>::try_from(serialized_old_values.len())?;
                let serialized_new_values_len = <u32>::try_from(serialized_new_values.len())?;

                let err = (self.get_upsert()?)(
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
                    Err(Self::Error::Ffi("$name upsert error".to_string(), err))
                }
            }

            async fn insert(
                &self,
                map: HashMap<Self::Token, EncryptedValue<$value_length>>,
            ) -> Result<(), Self::Error> {
                let serialized_map = serialize_edx_lines(&map)?;
                let serialized_map_len = <u32>::try_from(serialized_map.len())?;

                let err = (self.get_insert()?)(serialized_map.as_ptr(), serialized_map_len);

                if err == ErrorCode::Success.code() {
                    Ok(())
                } else {
                    Err(Self::Error::Ffi("$name insert".to_string(), err))
                }
            }

            async fn delete(
                &self,
                uids: std::collections::HashSet<Self::Token>,
            ) -> Result<(), Self::Error> {
                let serialized_uids = serialize_uid_set(&uids)?;
                let serialized_uids_len = <u32>::try_from(serialized_uids.len())?;

                let err = (self.get_delete()?)(serialized_uids.as_ptr(), serialized_uids_len);

                if err != ErrorCode::Success.code() {
                    return Err(Self::Error::Ffi("$name delete".to_string(), err));
                }
                Ok(())
            }
        }
    };
}
