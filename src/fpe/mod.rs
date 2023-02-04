/// The Key Length: 256 bit = 32 bytes for AES 256
pub const KEY_LENGTH: usize = 32;

mod alphabet;
pub use alphabet::Alphabet;

mod decimal;
pub use decimal::Decimal;

#[cfg(test)]
mod tests;
