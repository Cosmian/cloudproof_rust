mod alphabet;
pub use alphabet::Alphabet;

mod integer;
pub use integer::Integer;

mod float;
pub use float::Float;

mod error;
pub use error::AnoError;

#[cfg(test)]
mod tests;

/// The Key Length: 256 bit = 32 bytes for AES 256
pub const KEY_LENGTH: usize = 32;
