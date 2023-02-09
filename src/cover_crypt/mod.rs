//! Implement interfaces with other languages.

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "python")]
pub mod pyo3;

#[cfg(feature = "wasm_bindgen")]
pub mod wasm_bindgen;

#[cfg(test)]
mod tests {
    use cosmian_cover_crypt::{
        abe_policy::{EncryptionHint, Policy, PolicyAxis},
        Error,
    };

    pub fn policy() -> Result<Policy, Error> {
        let sec_level = PolicyAxis::new(
            "Security Level",
            vec![
                ("Protected", EncryptionHint::Classic),
                ("Confidential", EncryptionHint::Classic),
                ("Top Secret", EncryptionHint::Hybridized),
            ],
            true,
        );
        let department = PolicyAxis::new(
            "Department",
            vec![
                ("R&D", EncryptionHint::Classic),
                ("HR", EncryptionHint::Classic),
                ("MKG", EncryptionHint::Classic),
                ("FIN", EncryptionHint::Classic),
            ],
            false,
        );
        let mut policy = Policy::new(100);
        policy.add_axis(sec_level)?;
        policy.add_axis(department)?;
        Ok(policy)
    }
}
