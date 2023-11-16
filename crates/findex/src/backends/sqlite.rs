//! `SQLite` implementation of the Findex backends.

use std::{collections::HashMap, ops::Deref, sync::RwLock};

use async_trait::async_trait;
use cosmian_crypto_core::Nonce;
use cosmian_findex::{EdxStore, EncryptedValue, Token, ENTRY_LENGTH, LINK_LENGTH, NONCE_LENGTH};
use rusqlite::{params_from_iter, Connection, OptionalExtension};

use crate::backends::BackendError;

/// Implements the `SQLite` backend for the given `$type`, with values of size
/// `$value_length`.
macro_rules! impl_sqlite_backend {
    ($type:ident, $value_length:ident, $table_name:literal) => {
        impl $type {
            pub fn new(db_path: &str) -> Result<Self, BackendError> {
                let connection = Connection::open(db_path)?;
                connection
                    .execute(
                        &format!(
                            "CREATE TABLE IF NOT EXISTS {} (
                             uid               BLOB PRIMARY KEY,
                             nonce             BLOB NOT NULL,
                             ciphertext        BLOB NOT NULL,
                             tag               BLOB NOT NULL
                         )",
                            $table_name
                        ),
                        [],
                    )
                    .unwrap();
                Ok($type(RwLock::new(connection)))
            }
        }

        impl Deref for $type {
            type Target = RwLock<Connection>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        #[async_trait(?Send)]
        impl EdxStore<$value_length> for $type {
            type Error = BackendError;

            async fn dump_tokens(&self) -> Result<cosmian_findex::Tokens, Self::Error> {
                let cnx = self.read().expect("poisoned mutex");

                let mut stmt = cnx.prepare(&format!("SELECT uid FROM {}", $table_name))?;

                let rows = stmt.query_map([], |row| {
                    let token = Token::from(row.get::<_, [u8; cosmian_findex::Token::LENGTH]>(0)?);
                    Ok(token)
                })?;

                rows.collect::<Result<_, _>>().map_err(Self::Error::from)
            }

            async fn fetch(
                &self,
                tokens: cosmian_findex::Tokens,
            ) -> Result<cosmian_findex::TokenWithEncryptedValueList<$value_length>, Self::Error>
            {
                let cnx = self.read().expect("poisoned mutex");
                let mut stmt = cnx.prepare(&format!(
                    "SELECT uid, nonce, ciphertext, tag FROM {} WHERE uid IN ({})",
                    $table_name,
                    (0..tokens.len()).map(|_| "?").collect::<Vec<_>>().join(",")
                ))?;
                let rows = stmt.query_map(
                    params_from_iter(
                        tokens
                            .into_iter()
                            .map(<[u8; cosmian_findex::Token::LENGTH]>::from),
                    ),
                    |row| {
                        let token = row.get::<_, [u8; cosmian_findex::Token::LENGTH]>(0)?;
                        let nonce = row.get::<_, [u8; NONCE_LENGTH]>(1)?;
                        let ciphertext = row.get(2)?;
                        let tag = row.get(3)?;
                        Ok((
                            Token::from(token),
                            EncryptedValue {
                                nonce: Nonce::from(nonce),
                                ciphertext,
                                tag,
                            },
                        ))
                    },
                )?;

                rows.collect::<Result<_, _>>().map_err(Self::Error::from)
            }

            async fn upsert(
                &self,
                old_values: cosmian_findex::TokenToEncryptedValueMap<$value_length>,
                new_values: cosmian_findex::TokenToEncryptedValueMap<$value_length>,
            ) -> Result<cosmian_findex::TokenToEncryptedValueMap<$value_length>, Self::Error> {
                let mut conflicting_values = HashMap::with_capacity(new_values.len());
                let modifications = new_values
                    .into_iter()
                    .map(|(token, new_value)| (token, (old_values.get(&token), new_value)));

                let mut cnx = self.write().expect("poisoned mutex");
                let tx = cnx.transaction()?;
                for (token, (old_value, new_value)) in modifications {
                    let token_bytes: [u8; Token::LENGTH] = token.into();
                    let indexed_value = tx
                        .query_row(
                            &format!(
                                "SELECT nonce, ciphertext, tag FROM {} WHERE uid = ?1",
                                $table_name
                            ),
                            [token_bytes],
                            |row| {
                                let nonce = row.get::<_, [u8; NONCE_LENGTH]>(0)?;
                                let ciphertext = row.get(1)?;
                                let tag = row.get(2)?;
                                Ok(EncryptedValue {
                                    nonce: Nonce::from(nonce),
                                    ciphertext,
                                    tag,
                                })
                            },
                        )
                        .optional()?;
                    if indexed_value.as_ref() == old_value {
                        tx.execute(
                            &format!(
                                "REPLACE INTO {} (uid, nonce, ciphertext, tag) VALUES (?1, ?2, \
                                 ?3, ?4)",
                                $table_name,
                            ),
                            [
                                &*token,
                                new_value.nonce.0.as_slice(),
                                new_value.ciphertext.as_slice(),
                                new_value.tag.as_slice(),
                            ],
                        )?;
                    } else {
                        conflicting_values.insert(
                            token,
                            indexed_value.ok_or_else(|| {
                                Self::Error::Other(
                                    "Index values cannot be removed while upserting.".to_string(),
                                )
                            })?,
                        );
                    }
                }
                tx.commit()?;

                Ok(cosmian_findex::TokenToEncryptedValueMap::from(
                    conflicting_values,
                ))
            }

            async fn insert(
                &self,
                items: cosmian_findex::TokenToEncryptedValueMap<$value_length>,
            ) -> Result<(), Self::Error> {
                let mut cnx = self.write().expect("poisoned mutex");
                let tx = cnx.transaction()?;
                for (token, value) in items {
                    tx.execute(
                        &format!(
                            "INSERT INTO {} (uid, nonce, ciphertext, tag) VALUES (?1, ?2, ?3, ?4)",
                            $table_name
                        ),
                        [
                            &*token,
                            value.nonce.0.as_slice(),
                            value.ciphertext.as_slice(),
                            value.tag.as_slice(),
                        ],
                    )?;
                }
                tx.commit()?;

                Ok(())
            }

            async fn delete(&self, tokens: cosmian_findex::Tokens) -> Result<(), Self::Error> {
                let cnx = self.read().expect("poisoned mutex");
                let mut stmt = cnx.prepare(&format!(
                    "DELETE FROM {} WHERE uid IN ({})",
                    $table_name,
                    (0..tokens.len()).map(|_| "?").collect::<Vec<_>>().join(",")
                ))?;

                stmt.execute(params_from_iter(
                    tokens.into_iter().map(<[u8; Token::LENGTH]>::from),
                ))?;
                Ok(())
            }
        }
    };
}

#[derive(Debug)]
pub struct SqlEntryBackend(RwLock<Connection>);

impl_sqlite_backend!(SqlEntryBackend, ENTRY_LENGTH, "entry_table");

#[derive(Debug)]
pub struct SqlChainBackend(RwLock<Connection>);

impl_sqlite_backend!(SqlChainBackend, LINK_LENGTH, "chain_table");

#[cfg(test)]
mod tests {
    use std::path::Path;

    use futures::executor::block_on;

    use super::*;
    use crate::{
        backends::tests::{test_backend, test_non_regression},
        BackendConfiguration,
    };

    #[test]
    fn test_sqlite_backend() {
        let db_path = Path::new("../../target/sqlite.db");
        if db_path.exists() {
            std::fs::remove_file(db_path).unwrap();
        }
        let config = BackendConfiguration::Sqlite(
            db_path.to_str().unwrap().to_string(),
            db_path.to_str().unwrap().to_string(),
        );
        block_on(test_backend(config));
    }

    #[test]
    fn test_sqlite_non_regression() {
        let db_path = "datasets/sqlite.db";
        let entry_backend = SqlEntryBackend::new(db_path).unwrap();
        let chain_backend = SqlChainBackend::new(db_path).unwrap();
        block_on(test_non_regression(entry_backend, chain_backend));
    }
}
