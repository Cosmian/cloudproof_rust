# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2023-04-25

### Features

- Reexport CoveCrypt and Crypto Core

## [1.1.0] - 2023-03-30

### Features

- Expose Format-Preserving-Encryption (FPE) in FFI, Webassembly and Pyo3 interfaces:
  * expose integer and big integers encryption (as string with radix and digits)
  * expose string encryption according to given alphabet
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
  * expose float encryption

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
