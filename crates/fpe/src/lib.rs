pub mod core;

static ALPHABET_LIST: &[&str] = &[
    "numeric",
    "hexa_decimal",
    "alpha_lower",
    "alpha_upper",
    "alpha",
    "alpha_numeric",
    "utf",
    "chinese",
    "latin1sup",
    "latin1sup_alphanum",
];

pub(crate) fn get_alphabet(alphabet_id: &str) -> Result<core::Alphabet, core::AnoError> {
    let alphabet = match alphabet_id {
        "numeric" => core::Alphabet::numeric(),
        "hexa_decimal" => core::Alphabet::hexa_decimal(),
        "alpha_lower" => core::Alphabet::alpha_lower(),
        "alpha_upper" => core::Alphabet::alpha_upper(),
        "alpha" => core::Alphabet::alpha(),
        "alpha_numeric" => core::Alphabet::alpha_numeric(),
        "utf" => core::Alphabet::utf(),
        "chinese" => core::Alphabet::chinese(),
        "latin1sup" => core::Alphabet::latin1sup(),
        "latin1sup_alphanum" => core::Alphabet::latin1sup_alphanum(),
        _ => {
            return Err(core::AnoError::FPE(format!(
                "Cannot instantiate from this id: {alphabet_id}. Possible values are \
                 {ALPHABET_LIST:?}"
            )));
        }
    };
    Ok(alphabet)
}

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "python")]
pub mod pyo3;

#[cfg(feature = "wasm_bindgen")]
pub mod wasm_bindgen;
