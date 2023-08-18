use std::fmt::Display;

use crate::backends::BackendError;

#[derive(Debug, Clone, Hash, PartialEq, Eq, Copy)]
#[repr(u8)]
pub enum CallbackPrefix {
    Fetch = 0,
    Insert = 1,
    Upsert = 2,
    Delete = 3,
    DumpTokens = 4,
}

impl CallbackPrefix {
    #[cfg(feature = "backend-cloud")]
    pub fn get_uri(self) -> &'static str {
        match self {
            Self::Fetch => "fetch",
            Self::Insert => "insert",
            Self::Upsert => "upsert",
            Self::Delete => "delete",
            Self::DumpTokens => "dump_tokens",
        }
    }
}

impl TryFrom<u8> for CallbackPrefix {
    type Error = BackendError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Fetch),
            1 => Ok(Self::Insert),
            2 => Ok(Self::Upsert),
            3 => Ok(Self::Delete),
            4 => Ok(Self::DumpTokens),
            _ => Err(Self::Error::MissingCallback(format!(
                "no callback associated to code {value}"
            ))),
        }
    }
}

impl Display for CallbackPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fetch => write!(f, "fetch"),
            Self::Insert => write!(f, "insert"),
            Self::Upsert => write!(f, "upsert"),
            Self::Delete => write!(f, "delete"),
            Self::DumpTokens => write!(f, "dump tokens"),
        }
    }
}
