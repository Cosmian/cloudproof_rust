/// The Key Length: 256 bit = 32 bytes for AES 256
pub const KEY_LENGTH: usize = 32;

mod alphabet;
pub use alphabet::{Alphabet, FpeAlphabet};

mod numeral;
pub use numeral::Decimal;

#[cfg(test)]
mod tests;
