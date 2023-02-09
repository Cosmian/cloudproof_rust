<<<<<<< HEAD
# Cosmian Cloudproof Data Protection Library
=======
## CloudproofRust
>>>>>>> c8dba97 (feat: get callback errors from Findex)

![Build status](https://github.com/Cosmian/crypto_core/actions/workflows/ci.yml/badge.svg)
![Build status](https://github.com/Cosmian/crypto_core/actions/workflows/audit.yml/badge.svg)
![latest version](<https://img.shields.io/crates/v/cosmian_crypto_core.svg>)

This crate implements the WASM, FFI and python interfaces to the cryptographic
libraries used in Cosmian Cloudproof libraries for other languages:

- CoverCrypt;
- Findex;
- FPE;

<<<<<<< HEAD
<!-- toc -->

- [Format Preserving Encryption (FPE)](#format-preserving-encryption-fpe)
  - [Implementation](#implementation)
  - [Using FPE](#using-fpe)
    - [Encrypting Text](#encrypting-text)
      - [Encrypting and decrypting an alphanumeric text](#encrypting-and-decrypting-an-alphanumeric-text)
      - [Encrypting and decrypting a credit card number](#encrypting-and-decrypting-a-credit-card-number)
      - [Encrypting and decrypting a Chinese text with spaces](#encrypting-and-decrypting-a-chinese-text-with-spaces)
    - [Encrypting Integers](#encrypting-integers)
    - [Encrypting Floats](#encrypting-floats)
- [Benchmarks](#benchmarks)
  - [Run quick start](#run-quick-start)
  - [Run detailed report (Linux, MacOS)](#run-detailed-report-linux-macos)

<!-- tocstop -->

## Format Preserving Encryption (FPE)
=======

<!-- toc -->

- [Getting started](#getting-started)
- [Building and Testing](#building-and-testing)
  - [Build](#build)
  - [Use](#use)
  - [Run tests and benchmarks](#run-tests-and-benchmarks)
- [Features and Benchmarks](#features-and-benchmarks)
  - [Asymmetric Crypto](#asymmetric-crypto)
  - [Symmetric Crypto](#symmetric-crypto)
  - [Random Number Generator (RNG)](#random-number-generator-rng)
  - [Key Derivation Function (KDF)](#key-derivation-function-kdf)
- [Documentation](#documentation)

<!-- tocstop -->

## Building and Testing
>>>>>>> c8dba97 (feat: get callback errors from Findex)

### Features

<<<<<<< HEAD
### Implementation
=======
Sub-crates are used for each of cryptographic libraries and features are used
to select the proper interface. The available features are:
>>>>>>> c8dba97 (feat: get callback errors from Findex)

| wasm	 | selects code for the WASM interface 	 |
| ffi	 | selects code for the FFI interface	 |
| python | selects code for the Python interface |

The `cloudproof_findex` subcrate has an additional `cloud` feature used to
select the code to generate Findex Cloud interfaces. It should be combine with
one of the above features in order to generate an actual interface.

### Build

To install and build CloudproofRust, clone the repo:

<<<<<<< HEAD
### Using FPE

Cosmian FPE proposes 3 structures:

- `fpe::Alphabet` to encrypt text
- `fpe::Integer` to encrypt integers with various radixes
- `fpe::Float` to encrypt floating numbers

#### Encrypting Text

The `fpe::Alphabet` structure provides the ability to encrypt a plaintext using an `alphabet`.
Characters of the plaintext that belong to the alphabet are encrypted while the others are left unchanged at their original location in the ciphertext.

An alphabet can be instantiated using the `Alphabet::instantiate()` method:

```rust
let hexadecimal_alphabet = Alphabet::instantiate("01234567890abcdef").unwrap();
=======
```bash
git clone https://github.com/Cosmian/crypto_core.git
>>>>>>> c8dba97 (feat: get callback errors from Findex)
```

In all the following commands, the `cloud` feature can be added in order to
build the cloud interface of Findex, e.g.: `--features cloud,wasm`.

**FFI**:

To build the FFI interface, run:
```bash
cargo build --release --features ffi
```
The `.so` libraries can then be found in `target/release/`.

**WASM**:

To build the WASM interface, run (replace `[library path]` by `findex` or
`cover_crypt`):
```bash
wasm-pack build --release [library path] --features wasm
```
The `.wasm` libraries can then be found in `[library path]/pkg/`.

**Python**:

To build the Python interface, run (replace `[library path]` by `findex` or
`cover_crypt`):
```bash
maturin build --release --manifest-path [library path]/Cargo.toml --features python
```
The `.whl` libraries can then be found in `target/wheels/`.

### Run tests and benchmarks

Tests can be run with:

```bash
cargo test --release --all-features
```

<<<<<<< HEAD
##### Encrypting and decrypting an alphanumeric text
=======
The benchmarks are available in the cryptographic libraries.
>>>>>>> c8dba97 (feat: get callback errors from Findex)

## Features and Benchmarks

The benchmarks given below are run on a Intel(R) Core(TM) i7-10750H CPU @ 3.20GHz.

### Asymmetric Crypto

This crate implements a Diffie-Hellman asymmetric key pair based on the
Curve25519. This is one of the fastest elliptic curves known at this time and
it offers 128 bits of security.

It uses the [Dalek](https://github.com/dalek-cryptography/curve25519-dalek)
implementation, which offers an implementation of the Ristretto technique to
construct a prime order group on the curve. This group is used to implement
the public key.

```c
Bench the Group-Scalar multiplication on which is based the Diffie-Helman key exchange
                        time:   [59.932 µs 60.131 µs 60.364 µs]
```

<<<<<<< HEAD
##### Encrypting and decrypting a credit card number
=======
### Symmetric Crypto
>>>>>>> c8dba97 (feat: get callback errors from Findex)

This crate implements a Data Encryption Method (DEM) based on the AES256-GCM
algorithm, as described in the [ISO 2004](https://www.shoup.net/iso/std6.pdf).
This implementation is 128-bits secure in both the classic and the post-quantum
models.

It uses the [`aes_gcm`](https://docs.rs/aes-gcm/latest/aes_gcm/index.html)
implementation of the AES GCM algorithm. This implementation makes use of the
AES instruction set when available, which allows for a high encryption speed.

```c
Bench the DEM encryption of a 2048-bytes message without additional data
                        time:   [2.7910 µs 2.7911 µs 2.7914 µs]

Bench the DEM decryption of a 2048-bytes message without additional data
                        time:   [2.7074 µs 2.7079 µs 2.7085 µs]
```

### Random Number Generator (RNG)

<<<<<<< HEAD
##### Encrypting and decrypting a Chinese text with spaces
=======
This crate uses the implementation of the CHACHA algorithm with 12 rounds from
the [`rand_chacha`](https://rust-random.github.io/rand/rand_chacha/index.html)
crate to construct our RNG. It is therefore 128-bits secure.
>>>>>>> c8dba97 (feat: get callback errors from Findex)

```c
Bench the generation of a cryptographic RNG
                        time:   [353.84 ns 353.96 ns 354.10 ns]
```

### Key Derivation Function (KDF)

<<<<<<< HEAD
#### Encrypting Integers
=======
This crate uses the pure rust implementation of the SHAKE128 algorithm from the
[sha3](https://docs.rs/sha3/latest/sha3) crate. This allows implementing a KDF
which 128-bits secure for input sizes of at least 256 bits (32 bytes).
>>>>>>> c8dba97 (feat: get callback errors from Findex)

```c
bench the KDF derivation of a 32-bytes IKM into a 64-bytes key
                        time:   [1.1065 µs 1.1067 µs 1.1070 µs]
```

## Documentation

The documentation can be generated using Cargo:

```bash
cargo docs
```

<<<<<<< HEAD
#### Encrypting Floats

The `fpe::Float` structure provides support for encrypting floats of type `f64`:

```rust
let key = [0_u8; 32];
let tweak = b"unique tweak";

let flt = Float::instantiate().unwrap();
let ciphertext = flt.encrypt(&key, tweak, 123_456.789_f64).unwrap();
assert_eq!(1.170438892319619e91_f64, ciphertext);

let plaintext = flt.decrypt(&key, tweak, ciphertext).unwrap();
assert_eq!(123_456.789_f64, plaintext);
```

## Benchmarks

### Run quick start

Run `cargo bench` from the root directory

### Run detailed report (Linux, MacOS)

1. Install criterion and criterion-table

   ```sh
   cargo install cargo-criterion
   cargo install criterion-table
   ```

2. From the root of the project, run

   ```bash
   bash ./benches/benches.sh
   ```

3. The benchmarks are then available in [./benches/BENCHMARKS.md](./benches/BENCHMARKS.md)
=======
It is also available on
[doc.rs](https://docs.rs/cosmian_crypto_core/latest/cosmian_crypto_core/).
>>>>>>> c8dba97 (feat: get callback errors from Findex)
