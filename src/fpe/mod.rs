mod alphabet;
pub use alphabet::Alphabet;

mod integer;
pub use integer::Integer;

mod float;
pub use float::Float;

#[cfg(test)]
mod tests;

/// The Key Length: 256 bit = 32 bytes for AES 256
pub const KEY_LENGTH: usize = 32;

// avoid importing rand in WASM
#[cfg(not(feature = "wasm"))]
use rand::{RngCore, SeedableRng};
#[cfg(not(feature = "wasm"))]
use rand_chacha::ChaCha20Rng;

/// Generate a random key using a cryptographically
/// secure random number generator that is suitable for use with FPE
#[cfg(not(feature = "wasm"))]
pub fn random_key() -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut key = [0_u8; KEY_LENGTH];
    rng.fill_bytes(&mut key);
    key
}
