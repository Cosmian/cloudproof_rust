#[cfg(not(feature = "wasm"))]
use std::time::SystemTime;
use std::{ops::Deref, str::FromStr};

use async_trait::async_trait;
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_findex::{kmac, DbInterface, ENTRY_LENGTH, LINK_LENGTH};
pub use cosmian_findex::{TokenToEncryptedValueMap, TokenWithEncryptedValueList, Tokens};
#[cfg(feature = "wasm")]
use js_sys::Date;
use reqwest::Client;

use super::{upsert_data::UpsertData, AuthorizationToken, CallbackPrefix};
use crate::{
    db_interfaces::DbInterfaceError,
    ser_de::ffi_ser_de::{
        deserialize_edx_lines, deserialize_token_set, serialize_edx_lines, serialize_token_set,
    },
};

/// The number of seconds of validity of the requests to the `Findex Cloud`
/// server. After this time, the request cannot be accepted by the backend. This
/// is done to prevent replay attacks.
pub const REQUEST_SIGNATURE_TIMEOUT_AS_SECS: u64 = 60;

/// Callback signature length.
pub const SIGNATURE_LENGTH: usize = 32;

/// Parameters needed to instantiate a REST backend.
#[derive(Debug, PartialEq, Eq)]
pub struct FindexCloudParameters {
    token: AuthorizationToken,
    url: String,
}

impl FindexCloudParameters {
    #[must_use]
    pub const fn new(token: AuthorizationToken, url: String) -> Self {
        Self { token, url }
    }

    pub fn from(token: &str, url: String) -> Result<Self, DbInterfaceError> {
        let token = AuthorizationToken::from_str(token)?;
        Ok(Self { token, url })
    }
}

#[derive(Debug)]
pub struct FindexCloudChainBackend(FindexCloudParameters);

impl Deref for FindexCloudChainBackend {
    type Target = FindexCloudParameters;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FindexCloudChainBackend {
    #[must_use]
    pub const fn new(parameters: FindexCloudParameters) -> Self {
        Self(parameters)
    }

    /// Post the given `body` signed with the given `callback` key.
    async fn post(
        &self,
        callback: CallbackPrefix,
        bytes: &[u8],
    ) -> Result<Vec<u8>, DbInterfaceError> {
        let key = {
            self.token
                .get_key(&self.token.index_id, callback)
                .ok_or_else(|| DbInterfaceError::MissingPermission(callback as i32))?
        };

        // SystemTime::now() panics in WASM <https://github.com/rust-lang/rust/issues/48564>
        #[cfg(feature = "wasm")]
        let current_timestamp = (Date::now() / 1000.0) as u64; // Date::now() returns milliseconds

        #[cfg(not(feature = "wasm"))]
        let current_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| DbInterfaceError::Other("SystemTime is before UNIX_EPOCH".to_string()))?
            .as_secs();

        let expiration_timestamp_bytes =
            (current_timestamp + REQUEST_SIGNATURE_TIMEOUT_AS_SECS).to_be_bytes();

        let signature = kmac!(SIGNATURE_LENGTH, &key, &expiration_timestamp_bytes, bytes);

        let mut body =
            Vec::with_capacity(signature.len() + expiration_timestamp_bytes.len() + bytes.len());
        body.extend(&signature);
        body.extend(&expiration_timestamp_bytes);
        body.extend(bytes);

        let url = {
            format!(
                "{}/indexes/{}/{}",
                &self.url,
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
                DbInterfaceError::Other(format!(
                    "Unable to send the request to Findex Cloud: {err}"
                ))
            })?;

        if !response.status().is_success() {
            return Err(DbInterfaceError::Other(format!(
                "request to Findex Cloud server failed, status code is {}, response is '{}'",
                response.status(),
                response
                    .text()
                    .await
                    .unwrap_or_else(|_| "cannot parse response".to_owned())
            )));
        }

        response.bytes().await.map(|r| r.to_vec()).map_err(|err| {
            DbInterfaceError::Other(format!(
                "Unable to read the returned bytes from Findex Cloud server: {err}"
            ))
        })
    }
}

#[async_trait(?Send)]
impl DbInterface<LINK_LENGTH> for FindexCloudChainBackend {
    type Error = DbInterfaceError;

    async fn dump_tokens(&self) -> Result<Tokens, Self::Error> {
        let bytes = self.post(CallbackPrefix::DumpTokens, &[]).await?;
        deserialize_token_set(&bytes)
            .map_err(Self::Error::from)
            .map(Into::into)
    }

    async fn fetch(
        &self,
        tokens: Tokens,
    ) -> Result<TokenWithEncryptedValueList<LINK_LENGTH>, Self::Error> {
        let bytes = serialize_token_set(&tokens)?;
        let res = self
            .post((CallbackPrefix::FetchEntry as u8 + 1).try_into()?, &bytes)
            .await?;
        deserialize_edx_lines(&res)
            .map_err(Self::Error::from)
            .map(Into::into)
    }

    async fn upsert(
        &self,
        old_values: TokenToEncryptedValueMap<LINK_LENGTH>,
        new_values: TokenToEncryptedValueMap<LINK_LENGTH>,
    ) -> Result<TokenToEncryptedValueMap<LINK_LENGTH>, Self::Error> {
        let modifications = UpsertData::<LINK_LENGTH>::new(old_values, new_values);
        let bytes = modifications.serialize()?;

        let res = self.post(CallbackPrefix::Upsert, &bytes).await?;

        deserialize_edx_lines(&res)
            .map(|v| v.into_iter().collect())
            .map_err(Self::Error::from)
    }

    async fn insert(
        &self,
        values: TokenToEncryptedValueMap<LINK_LENGTH>,
    ) -> Result<(), Self::Error> {
        let bytes = serialize_edx_lines(&values)?;
        let _ = self.post(CallbackPrefix::Insert, &bytes).await?;
        Ok(())
    }

    async fn delete(&self, tokens: Tokens) -> Result<(), Self::Error> {
        let bytes = serialize_token_set(&tokens)?;
        let _ = self
            .post((CallbackPrefix::DeleteEntry as u8 + 1).try_into()?, &bytes)
            .await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct FindexCloudEntryBackend(FindexCloudParameters);

impl Deref for FindexCloudEntryBackend {
    type Target = FindexCloudParameters;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FindexCloudEntryBackend {
    #[must_use]
    pub const fn new(parameters: FindexCloudParameters) -> Self {
        Self(parameters)
    }

    /// Post the given `body` signed with the given `callback` key.
    async fn post(
        &self,
        callback: CallbackPrefix,
        bytes: &[u8],
    ) -> Result<Vec<u8>, DbInterfaceError> {
        let key = {
            self.token
                .get_key(&self.token.index_id, callback)
                .ok_or_else(|| DbInterfaceError::MissingPermission(callback as i32))?
        };

        // SystemTime::now() panics in WASM <https://github.com/rust-lang/rust/issues/48564>
        #[cfg(feature = "wasm")]
        let current_timestamp = (Date::now() / 1000.0) as u64; // Date::now() returns milliseconds

        #[cfg(not(feature = "wasm"))]
        let current_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| DbInterfaceError::Other("SystemTime is before UNIX_EPOCH".to_string()))?
            .as_secs();

        let expiration_timestamp_bytes =
            (current_timestamp + REQUEST_SIGNATURE_TIMEOUT_AS_SECS).to_be_bytes();

        let signature = kmac!(SIGNATURE_LENGTH, &key, &expiration_timestamp_bytes, bytes);

        let mut body =
            Vec::with_capacity(signature.len() + expiration_timestamp_bytes.len() + bytes.len());
        body.extend(&signature);
        body.extend(&expiration_timestamp_bytes);
        body.extend(bytes);

        let url = {
            format!(
                "{}/indexes/{}/{}",
                &self.url,
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
                DbInterfaceError::Other(format!(
                    "Unable to send the request to Findex Cloud: {err}"
                ))
            })?;

        if !response.status().is_success() {
            return Err(DbInterfaceError::Other(format!(
                "request to Findex Cloud server failed, status code is {}, response is '{}'",
                response.status(),
                response
                    .text()
                    .await
                    .unwrap_or_else(|_| "cannot parse response".to_owned())
            )));
        }

        response.bytes().await.map(|r| r.to_vec()).map_err(|err| {
            DbInterfaceError::Other(format!(
                "Unable to read the returned bytes from Findex Cloud server: {err}"
            ))
        })
    }
}

#[async_trait(?Send)]
impl DbInterface<ENTRY_LENGTH> for FindexCloudEntryBackend {
    type Error = DbInterfaceError;

    async fn dump_tokens(&self) -> Result<cosmian_findex::Tokens, Self::Error> {
        let bytes = self.post(CallbackPrefix::DumpTokens, &[]).await?;
        deserialize_token_set(&bytes)
            .map_err(Self::Error::from)
            .map(Into::into)
    }

    async fn fetch(
        &self,
        tokens: Tokens,
    ) -> Result<TokenWithEncryptedValueList<ENTRY_LENGTH>, Self::Error> {
        let bytes = serialize_token_set(&tokens)?;
        let res = self
            .post((CallbackPrefix::FetchEntry as u8).try_into()?, &bytes)
            .await?;
        deserialize_edx_lines(&res)
            .map_err(Self::Error::from)
            .map(Into::into)
    }

    async fn upsert(
        &self,
        old_values: TokenToEncryptedValueMap<ENTRY_LENGTH>,
        new_values: TokenToEncryptedValueMap<ENTRY_LENGTH>,
    ) -> Result<TokenToEncryptedValueMap<ENTRY_LENGTH>, Self::Error> {
        let modifications = UpsertData::<ENTRY_LENGTH>::new(old_values, new_values);
        let bytes = modifications.serialize()?;

        let res = self.post(CallbackPrefix::Upsert, &bytes).await?;

        deserialize_edx_lines(&res)
            .map(|v| v.into_iter().collect())
            .map_err(Self::Error::from)
    }

    async fn insert(
        &self,
        values: TokenToEncryptedValueMap<ENTRY_LENGTH>,
    ) -> Result<(), Self::Error> {
        let bytes = serialize_edx_lines(&values)?;
        let _ = self.post(CallbackPrefix::Insert, &bytes).await?;
        Ok(())
    }

    async fn delete(&self, tokens: Tokens) -> Result<(), Self::Error> {
        let bytes = serialize_token_set(&tokens)?;
        let _ = self
            .post((CallbackPrefix::DeleteEntry as u8).try_into()?, &bytes)
            .await?;
        Ok(())
    }
}
