use async_trait::async_trait;
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_findex::{DbInterface, ENTRY_LENGTH, LINK_LENGTH};
pub use cosmian_findex::{TokenToEncryptedValueMap, TokenWithEncryptedValueList, Tokens};
use reqwest::Client;

use super::{upsert_data::UpsertData, CallbackPrefix};
use crate::{
    db_interfaces::DbInterfaceError,
    ser_de::ffi_ser_de::{
        deserialize_edx_lines, deserialize_token_set, serialize_edx_lines, serialize_token_set,
    },
};

#[derive(Debug)]
pub struct RestEntryBackend {
    pub client: Client,
    pub url: String,
}

impl RestEntryBackend {
    async fn post(
        &self,
        callback: CallbackPrefix,
        body: &[u8],
    ) -> Result<Vec<u8>, DbInterfaceError> {
        let url = { format!("{}/indexes/{}", &self.url, callback.get_uri(),) };
        let response = self
            .client
            .post(url)
            .body(body.to_vec())
            .send()
            .await
            .map_err(|err| {
                DbInterfaceError::Other(format!("Unable to send the request to Findex REST: {err}"))
            })?;

        if !response.status().is_success() {
            return Err(DbInterfaceError::Other(format!(
                "request to Findex REST server failed, status code is {}, response is '{}'",
                response.status(),
                response
                    .text()
                    .await
                    .unwrap_or_else(|_| "cannot parse response".to_owned())
            )));
        }

        response.bytes().await.map(|r| r.to_vec()).map_err(|err| {
            DbInterfaceError::Other(format!(
                "Unable to read the returned bytes from Findex REST server: {err}"
            ))
        })
    }
}

#[async_trait(?Send)]
impl DbInterface<ENTRY_LENGTH> for RestEntryBackend {
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

#[derive(Debug)]
pub struct RestChainBackend {
    pub client: Client,
    pub url: String,
}

impl RestChainBackend {
    async fn post(
        &self,
        callback: CallbackPrefix,
        body: &[u8],
    ) -> Result<Vec<u8>, DbInterfaceError> {
        let url = { format!("{}/indexes/{}", &self.url, callback.get_uri(),) };

        let response = self
            .client
            .post(url)
            .body(body.to_vec())
            .send()
            .await
            .map_err(|err| {
                DbInterfaceError::Other(format!("Unable to send the request to Findex REST: {err}"))
            })?;

        if !response.status().is_success() {
            return Err(DbInterfaceError::Other(format!(
                "request to Findex REST server failed, status code is {}, response is '{}'",
                response.status(),
                response
                    .text()
                    .await
                    .unwrap_or_else(|_| "cannot parse response".to_owned())
            )));
        }

        response.bytes().await.map(|r| r.to_vec()).map_err(|err| {
            DbInterfaceError::Other(format!(
                "Unable to read the returned bytes from Findex REST server: {err}"
            ))
        })
    }
}

#[async_trait(?Send)]
impl DbInterface<LINK_LENGTH> for RestChainBackend {
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
