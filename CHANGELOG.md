# Changelog

All notable changes to this project will be documented in this file.

## [2.2.3] - 2023-09-19

### Bug Fixes

- Use Findex with the `stable` toolchain ([#45])

### Features

- Upgrade crypto_core to 9.2.0

## [2.2.2] - 2023-09-01

### Features

- Upgrade crypto_core to 9.1.0

## [2.2.1] - 2023-08-17

### Bug Fixes

- Reexport `Findex` features in `cloudproof` crate

## [2.2.0] - 2023-08-04

### Features

- Upgrade to Findex 5.0.0
- Added full Findex over Redis implementation

### Ci

- Added Macos support for Pyo3 builds

### Bug Fixes

- Better separation of core and tests for Findex implementation over Sqlite

## [2.1.1] - 2023-07-18

### Bug Fixes

- Only use native types u8, i8, u32, i32, etc.
- clean github artifacts

### Features

- Add cpp_compat to cbindgen.toml

## [2.1.0] - 2023-07-11

### Features

- Add ECIES and AES256GCM bindings and add logs on findex callbacks
- Merge all new crates to cloudproof crate
- Use crypto_core v9.0
- Use cover_crypt v12.0

### Ci

- Freeze cloudproof github workflow
- Bump kms to 4.4.2

## [2.0.2] - 2023-06-05

### Ci

- Publish python packages individually

## [2.0.1] - 2023-06-02

### Bug Fixes

- Re-include feature cloud in cloudproof crate
- Use Findex v4.0.1 to fix race condition in fetch_chains()

## [2.0.0] - 2023-06-01

### Features

- upgrade Findex (v3.0.0 -> v4.0.0):
  - change indexed values size (require a reset of the index database)
  - change search interface
    - change parameter order
    - remove `fetch_chains_batch_size`
    - remove `max_results_per_keyword`
    - remove `max_depth`
    - searching for a non indexed keyword leads to an empty `HashSet` for this
      keyword in the search results instead of this keyword being missing from
      the results.
    - support multiple fetch entry tables:
      - Add entry table number in FFI functions in order to pre-allocate the output buffer size in fetching callbacks
  - change upsert interface:
    - add deletions
  - change compact interface:
    - change parameter order
  - add compact live behind the `compact_live` feature
- add data anonymization methods such as:
  - noise methods
  - hash methods
  - number methods
  - word methods

## [1.3.0] - 2023-04-26

### Features

- Make cloudproof crate publishable and publish it in CI on tags

## [1.2.0] - 2023-04-25

### Features

- Reexport CoveCrypt and Crypto Core

## [1.1.0] - 2023-03-30

### Features

- Expose Format-Preserving-Encryption (FPE) in FFI, Webassembly and Pyo3 interfaces:
  - expose integer and big integers encryption (as string with radix and digits)
  - expose string encryption according to given alphabet
    - "numeric": 0123456789
    - "hexa_decimal": 0123456789abcdef
    - "alpha_lower": abcdefghijklmnopqrstuvwxyz
    - "alpha_upper": ABCDEFGHIJKLMNOPQRSTUVWXYZ
    - "alpha": abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
    - "alpha_numeric": 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
    - "utf": creates an Alphabet with the first 63489 (~2^16) Unicode characters
    - "chinese": creates an Alphabet with the Chinese characters
    - "latin1sup": creates an Alphabet with the latin-1 and latin1-supplement characters (supports French)
    - "latin1sup_alphanum": creates an Alphabet with the latin-1 and latin1-supplement characters but without the non alphanumeric characters (supports French)
  - expose float encryption

## [1.0.1] - 2023-03-08

### Features

- Add the meta crate `cloudproof` in order to build 1 shared library containing both cover_crypt and findex

## [1.0.0] - 2023-03-07

### Documentation

- Create README.md

### Features

- Add existing findex and cover_crypt source code
- Get callback errors from Findex
- Add RusqliteFindex implementation
- Define workspace dependencies and mutualize findex and cover_crypt to 7.0.0
- Wrap FindexCloud in Pyo3

### Refactor

- Rebase on cover_crypt 11
