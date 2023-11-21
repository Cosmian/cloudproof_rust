use std::fmt::Display;

use crate::backends::BackendError;

#[derive(Debug, Clone, Hash, PartialEq, Eq, Copy)]
#[repr(u8)]
pub enum CallbackPrefix {
    FetchEntry = 0,
    FetchChain = 1,
    Insert = 2,
    Upsert = 3,
    DeleteEntry = 4,
    DeleteChain = 5,
    DumpTokens = 6,
}

impl CallbackPrefix {
    #[cfg(feature = "backend-rest")]
    #[must_use]
    pub fn get_uri(self) -> &'static str {
        match self {
            Self::FetchEntry => "fetch_entries",
            Self::FetchChain => "fetch_chains",
            Self::Insert => "insert_chains",
            Self::Upsert => "upsert_entries",
            Self::DeleteEntry => "delete_entries",
            Self::DeleteChain => "delete_chains",
            Self::DumpTokens => "dump_tokens",
        }
    }
}

impl TryFrom<u8> for CallbackPrefix {
    type Error = BackendError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::FetchEntry),
            1 => Ok(Self::FetchChain),
            2 => Ok(Self::Insert),
            3 => Ok(Self::Upsert),
            4 => Ok(Self::DeleteEntry),
            5 => Ok(Self::DeleteChain),
            6 => Ok(Self::DumpTokens),
            _ => Err(Self::Error::MissingCallback(format!(
                "no callback associated to code {value}"
            ))),
        }
    }
}

impl Display for CallbackPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FetchEntry => write!(f, "fetch entry"),
            Self::FetchChain => write!(f, "fetch chain"),
            Self::Insert => write!(f, "insert"),
            Self::Upsert => write!(f, "upsert"),
            Self::DeleteEntry => write!(f, "delete entry"),
            Self::DeleteChain => write!(f, "delete chain"),
            Self::DumpTokens => write!(f, "dump tokens"),
        }
    }
}
