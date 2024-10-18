use async_trait::async_trait;
use cosmian_findex::DbInterface;

use crate::db_interfaces::DbInterfaceError;

/// Implements `EdxStore<$value_length>` for the given backend type, which wraps
/// the given callback type.
///
/// This macro is needed because:
/// - two distinct backend types are needed for the interfaces so exposing a
///   single generic type is not possible;
/// - both types need to implement the same trait, for each interface;
macro_rules! impl_custom_backend {
    ($backend_type:ident, $callback_type:ident, $value_length:ident) => {
        impl $backend_type {
            #[must_use]
            pub const fn new(backend: $callback_type) -> Self {
                Self(backend)
            }
        }

        impl std::ops::Deref for $backend_type {
            type Target = $callback_type;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        #[$crate::db_interfaces::custom::async_trait(?Send)]
        impl $crate::db_interfaces::custom::DbInterface<$value_length> for $backend_type {
            type Error = $crate::db_interfaces::custom::DbInterfaceError;

            async fn dump_tokens(&self) -> Result<cosmian_findex::Tokens, Self::Error> {
                self.0.dump_tokens().await.map(Into::into)
            }

            async fn fetch(
                &self,
                uids: cosmian_findex::Tokens,
            ) -> Result<cosmian_findex::TokenWithEncryptedValueList<$value_length>, Self::Error>
            {
                self.0.fetch(uids.into()).await.map(Into::into)
            }

            async fn upsert(
                &self,
                old_values: cosmian_findex::TokenToEncryptedValueMap<$value_length>,
                new_values: cosmian_findex::TokenToEncryptedValueMap<$value_length>,
            ) -> Result<cosmian_findex::TokenToEncryptedValueMap<$value_length>, Self::Error> {
                self.0
                    .upsert(old_values.into(), new_values.into())
                    .await
                    .map(Into::into)
            }

            async fn insert(
                &self,
                new_items: cosmian_findex::TokenToEncryptedValueMap<$value_length>,
            ) -> Result<(), Self::Error> {
                self.0.insert(new_items.into()).await.map(Into::into)
            }

            async fn delete(&self, uids: cosmian_findex::Tokens) -> Result<(), Self::Error> {
                self.0.delete(uids.into()).await.map(Into::into)
            }
        }
    };
}

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "python")]
pub mod python;
