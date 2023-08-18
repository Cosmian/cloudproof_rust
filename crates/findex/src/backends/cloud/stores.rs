use std::ops::Deref;
#[cfg(not(feature = "wasm_bindgen"))]
use std::time::SystemTime;

use async_trait::async_trait;
use cosmian_findex::{kmac, EdxStore, ENTRY_LENGTH, LINK_LENGTH};
pub use cosmian_findex::{Token, TokenToEncryptedValueMap, TokenWithEncryptedValueList, Tokens};
#[cfg(feature = "wasm_bindgen")]
use js_sys::Date;
use reqwest::Client;

use super::FindexToken;
use crate::{
    backends::{BackendError, CallbackPrefix},
    ser_de::ffi_ser_de::{
        deserialize_edx_lines, deserialize_token_set, serialize_edx_lines, serialize_token_set,
    },
};

/// The number of seconds of validity of the requests to the Findex Cloud
/// backend. After this time, the request cannot be accepted by the backend.
/// This is done to prevent replay attacks.
pub const REQUEST_SIGNATURE_TIMEOUT_AS_SECS: u64 = 60;

/// Callback signature length.
pub const SIGNATURE_LENGTH: usize = 32;

pub const FINDEX_CLOUD_DEFAULT_DOMAIN: &str = "https://findex.cosmian.com";

macro_rules! impl_cloud_backend {
    ($type:ident, $value_length:ident, $name:literal) => {
        impl Deref for $type {
            type Target = CloudParameters;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl $type {
            pub fn new(parameters: CloudParameters) -> Self {
                Self(parameters)
            }

            /// Post the given `body` signed with the given `callback` key.
            async fn post(
                &self,
                callback: CallbackPrefix,
                bytes: &[u8],
            ) -> Result<Vec<u8>, BackendError> {
                let key = {
                    self.token
                        .get_key(callback)
                        .ok_or_else(|| BackendError::MissingPermission(callback as i32))?
                };

                // SystemTime::now() panics in WASM <https://github.com/rust-lang/rust/issues/48564>
                #[cfg(feature = "wasm_bindgen")]
                let current_timestamp = (Date::now() / 1000.0) as u64; // Date::now() returns milliseconds

                #[cfg(not(feature = "wasm_bindgen"))]
                let current_timestamp = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|_| {
                        BackendError::Other("SystemTime is before UNIX_EPOCH".to_string())
                    })?
                    .as_secs();

                let expiration_timestamp_bytes =
                    (current_timestamp + REQUEST_SIGNATURE_TIMEOUT_AS_SECS).to_be_bytes();

                let signature = kmac!(SIGNATURE_LENGTH, &key, &expiration_timestamp_bytes, bytes);

                let mut body = Vec::with_capacity(
                    signature.len() + expiration_timestamp_bytes.len() + bytes.len(),
                );
                body.extend(&signature);
                body.extend(&expiration_timestamp_bytes);
                body.extend(bytes);

                let url = {
                    format!(
                        "{}/indexes/{}/{}",
                        self.url.as_deref().unwrap_or(FINDEX_CLOUD_DEFAULT_DOMAIN),
                        self.token.index_id,
                        callback.get_uri(),
                    )
                };

                let response = Client::new()
                    .post(url)
                    .body(body)
                    .send()
                    .await
                    .map_err(|err| {
                        BackendError::Other(format!(
                            "Unable to send the request to FindexCloud: {err}"
                        ))
                    })?;

                if !response.status().is_success() {
                    return Err(BackendError::Other(format!(
                        "request to Findex Cloud failed, status code is {}, response is {}",
                        response.status(),
                        response
                            .text()
                            .await
                            .unwrap_or_else(|_| "cannot parse response".to_owned())
                    )));
                }

                response.bytes().await.map(|r| r.to_vec()).map_err(|err| {
                    BackendError::Other(format!(
                        "Impossible to read the returned bytes from FindexCloud: {err}"
                    ))
                })
            }
        }

        #[async_trait(?Send)]
        impl EdxStore<$value_length> for $type {
            type Error = BackendError;

            async fn dump_tokens(&self) -> Result<cosmian_findex::Tokens, Self::Error> {
                let bytes = self.post(CallbackPrefix::DumpTokens, &[]).await?;
                deserialize_token_set(&bytes)
                    .map_err(Self::Error::from)
                    .map(Into::into)
            }

            async fn fetch(
                &self,
                tokens: $crate::backends::cloud::stores::Tokens,
            ) -> Result<
                $crate::backends::cloud::stores::TokenWithEncryptedValueList<$value_length>,
                Self::Error,
            > {
                let bytes = serialize_token_set(&tokens.into())?;
                let res = self.post(CallbackPrefix::Fetch, &bytes).await?;
                deserialize_edx_lines(&res)
                    .map_err(Self::Error::from)
                    .map(Into::into)
            }

            async fn upsert(
                &self,
                old_values: $crate::backends::cloud::stores::TokenToEncryptedValueMap<
                    $value_length,
                >,
                new_values: $crate::backends::cloud::stores::TokenToEncryptedValueMap<
                    $value_length,
                >,
            ) -> Result<
                $crate::backends::cloud::stores::TokenToEncryptedValueMap<$value_length>,
                Self::Error,
            > {
                let serialized_old_values = serialize_edx_lines(&old_values.into())?;
                let serialized_new_values = serialize_edx_lines(&new_values.into())?;

                let res = self
                    .post(
                        CallbackPrefix::Fetch,
                        &[serialized_old_values, serialized_new_values].concat(),
                    )
                    .await?;

                deserialize_edx_lines(&res)
                    .map(|v| v.into_iter().collect())
                    .map_err(Self::Error::from)
            }

            async fn insert(
                &self,
                values: $crate::backends::cloud::stores::TokenToEncryptedValueMap<$value_length>,
            ) -> Result<(), Self::Error> {
                let bytes = serialize_edx_lines(&values.into())?;
                let _ = self.post(CallbackPrefix::Insert, &bytes).await?;
                Ok(())
            }

            async fn delete(
                &self,
                tokens: $crate::backends::cloud::stores::Tokens,
            ) -> Result<(), Self::Error> {
                let bytes = serialize_token_set(&tokens.into())?;
                let _ = self.post(CallbackPrefix::Delete, &bytes).await?;
                Ok(())
            }
        }
    };
}

/// Parameters needed to instantiate a cloud backend.
#[derive(Debug, PartialEq, Eq)]
pub struct CloudParameters {
    token: FindexToken,
    url: Option<String>,
}

impl CloudParameters {
    pub fn new(token: FindexToken, url: Option<String>) -> Self {
        Self { token, url }
    }
}

#[derive(Debug)]
pub struct CloudEntryBackend(CloudParameters);

impl_cloud_backend!(CloudEntryBackend, ENTRY_LENGTH, "entry_table");

#[derive(Debug)]
pub struct CloudChainBackend(CloudParameters);

impl_cloud_backend!(CloudChainBackend, LINK_LENGTH, "entry_table");
