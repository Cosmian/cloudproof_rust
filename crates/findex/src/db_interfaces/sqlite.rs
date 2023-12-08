//! `SQLite` implementation of the Findex backends.

use std::{collections::HashMap, ops::Deref, sync::RwLock};

use async_trait::async_trait;
use cosmian_findex::{DbInterface, EncryptedValue, Token, ENTRY_LENGTH, LINK_LENGTH};
use rusqlite::{params_from_iter, Connection, OptionalExtension};

use crate::db_interfaces::DbInterfaceError;

/// Implements the `SQLite` backend for the given `$type`, with values of size
/// `$value_length`.
macro_rules! impl_sqlite_backend {
    ($type:ident, $value_length:ident, $table_name:literal) => {
        impl $type {
            pub fn new(db_path: &str) -> Result<Self, DbInterfaceError> {
                let connection = Connection::open(db_path)?;
                connection
                    .execute(
                        &format!(
                            "CREATE TABLE IF NOT EXISTS {} (
                             uid               BLOB PRIMARY KEY,
                             value             BLOB NOT NULL
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
        impl DbInterface<$value_length> for $type {
            type Error = DbInterfaceError;

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
                    "SELECT uid, value FROM {} WHERE uid IN ({})",
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
                        let value =
                            row.get::<_, [u8; EncryptedValue::<$value_length>::LENGTH]>(1)?;
                        Ok((Token::from(token), value))
                    },
                )?;

                rows.map(|res| {
                    // TODO: this fix is needed since error from conversion to encrypted value is not
                    // easily convertible inside the `query_map`.
                    //
                    // Two paths to go forward:
                    // - find a way to convert the error inside `query_map`
                    // - find a way to convert without failure (currently blocked since constant
                    //   generics cannot be used in constant operations);
                    let (token, value) = res?;
                    let value = EncryptedValue::<$value_length>::try_from(value.as_slice())?;
                    Ok::<_, Self::Error>((token, value))
                })
                .collect::<Result<_, _>>()
                .map_err(Self::Error::from)
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
                    let old_value = old_value.map(|v| <Vec<u8>>::from(v));
                    let token_bytes: [u8; Token::LENGTH] = token.into();
                    let indexed_value = tx
                        .query_row(
                            &format!("SELECT value FROM {} WHERE uid = ?1", $table_name),
                            [token_bytes],
                            |row| row.get::<_, Vec<u8>>(0),
                        )
                        .optional()?;
                    if indexed_value == old_value {
                        tx.execute(
                            &format!("REPLACE INTO {} (uid, value) VALUES (?1, ?2)", $table_name),
                            [&*token, &<Vec<u8>>::from(&new_value)],
                        )?;
                    } else {
                        let indexed_value = indexed_value.ok_or_else(|| {
                            Self::Error::Other(
                                "Index values cannot be removed while upserting.".to_string(),
                            )
                        })?;
                        conflicting_values
                            .insert(token, EncryptedValue::try_from(indexed_value.as_slice())?);
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
                        &format!("INSERT INTO {} (uid, value) VALUES (?1, ?2)", $table_name),
                        [&*token, &<Vec<u8>>::from(&value)],
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

    use crate::{
        db_interfaces::tests::{
            test_backend, test_generate_non_regression_db, test_non_regression,
        },
        Configuration,
    };

    #[test]
    fn test_sqlite_backend() {
        let db_path = Path::new("../../target/sqlite_with_compact.db");
        if db_path.exists() {
            std::fs::remove_file(db_path).unwrap();
        }
        let config = Configuration::Sqlite(
            db_path.to_str().unwrap().to_string(),
            db_path.to_str().unwrap().to_string(),
        );
        block_on(test_backend(config));
    }

    #[test]
    fn test_sqlite_non_regression() {
        // Test creating a new non-regression database.
        let db_path = Path::new("../../target/sqlite.db");
        if db_path.exists() {
            std::fs::remove_file(db_path).unwrap();
        }

        let config = Configuration::Sqlite(
            db_path.to_str().unwrap().to_string(),
            db_path.to_str().unwrap().to_string(),
        );
        block_on(test_generate_non_regression_db(config.clone()));
        block_on(test_non_regression(config));

        // Test existing non-regression database.
        let db_path = Path::new("datasets/sqlite.db");
        let config = Configuration::Sqlite(
            db_path.to_str().unwrap().to_string(),
            db_path.to_str().unwrap().to_string(),
        );
        block_on(test_non_regression(config));
    }
}
