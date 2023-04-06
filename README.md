# Cosmian Cloudproof Data Protection Library

![Build status](https://github.com/Cosmian/cloudproof_rust/actions/workflows/ci.yml/badge.svg)
![Build status](https://github.com/Cosmian/cloudproof_rust/actions/workflows/build.yml/badge.svg)
![Build status](https://github.com/Cosmian/cloudproof_rust/actions/workflows/benches.yml/badge.svg)

Cloudproof Encryption provides libraries and tools to encrypt and securely index large repositories of data with advanced, high-performance security primitives with Post-Quantum resistance.

See [the use cases and benefits](https://docs.cosmian.com/cloudproof_encryption/use_cases_benefits/) and a description of the [cryptosystems](https://docs.cosmian.com/cloudproof_encryption/crypto_systems/) used.

The libraries are available in multiple languages to facilitate encryption close to the data source and decryption close to the decryption target, including mobile devices and browsers.

The Cloudproof Rust repository provides these interfaces such as FFI, WebAssembly and Pyo3 to run :

- **FFI** interface is used by:
  - [cloudproof_java](https://github.com/Cosmian/cloudproof_java): the Cloudproof Java Library
  - [cloudproof_flutter](https://github.com/Cosmian/cloudproof_flutter): the Cloudproof Flutter Library
- **WebAssembly** interface is used by:
  - [cloudproof_js](https://github.com/Cosmian/cloudproof_js): the Cloudproof Javascript Library
- **Pyo3** interface is used by:
  - [cloudproof_python](https://github.com/Cosmian/cloudproof_python): the Cloudproof Python Library

<!-- toc -->

- [Licensing](#licensing)
- [Cryptographic primitives](#cryptographic-primitives)
- [Building and testing](#building-and-testing)
  * [Building the library for `cloudproof_java`](#building-the-library-for-cloudproof_java)
  * [Building the library for `cloudproof_flutter`](#building-the-library-for-cloudproof_flutter)
  * [Build the library for `cloudproof_js`](#build-the-library-for-cloudproof_js)
  * [Build the library for `cloudproof_python`](#build-the-library-for-cloudproof_python)
  * [Building the library for a different glibc](#building-the-library-for-a-different-glibc)
- [Benchmarks](#benchmarks)
- [Documentation](#documentation)
  * [CoverCrypt](#covercrypt)
  * [Findex](#findex)
  * [Format Preserving Encryption](#format-preserving-encryption)
- [Releases](#releases)

<!-- tocstop -->

## Licensing

The library is available under a dual licensing scheme Affero GPL/v3 and commercial. See [LICENSE.md](LICENSE.md) for details.

## Cryptographic primitives

These interfaces are based on:

- [CoverCrypt](https://github.com/Cosmian/cover_crypt) algorithm which allows
creating ciphertexts for a set of attributes and issuing user keys with access
policies over these attributes. `CoverCrypt` offers Post-Quantum resistance.

- [Findex](https://github.com/Cosmian/findex) which is a cryptographic protocol designed to securely make search queries on
an untrusted cloud server. Thanks to its encrypted indexes, large databases can
securely be outsourced without compromising usability.

- [FPE](./crates/fpe/README.md) provides `Format Preserving Encryption` (FPE) techniques for use in a zero-trust environment. These techniques are based on FPE-FF1 which is described in [NIST:800-38G](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-38g.pdf).

## Building and testing

To build all interfaces (including the FFI, Wasm and Pyo3):

```bash
cargo build --release --all-features
```

The latter will build the shared libraries for `cover_crypt` and `findex`. On Linux, one can verify that the FFI symbols are present using:

```bash
objdump -T  target/release/libcosmian_cover_crypt.so
objdump -T  target/release/libcosmian_findex.so
```

The code contains numerous tests that you can run using:

```bash
cargo test --release --all-features
```

### Building the library for `cloudproof_java`

From the root directory:

```bash
cargo build --release --features ffi,cloud
```

The `.so` libraries can then be found in `target/release/`.

### Building the library for `cloudproof_flutter`

From the root directory:

```bash
cargo build --release --features ffi
```

The `.so` libraries can then be found in `target/release/`.

### Build the library for `cloudproof_js`

From the root directory:

```bash
wasm-pack build --release --features wasm_bindgen
```

The `.wasm` libraries can then be found in `pkg/`.

### Build the library for `cloudproof_python`

From the root directory:

```bash
maturin build --release --manifest-path crates/<cover_crypt or findex>/Cargo.toml --features python
```

**Note**: when a new function or class is added to the PyO3 interface, its
signature needs to be added to
[`**init**.pyi`](./crates/<cover_crypt or findex>/python/cloudproof_<cover_crypt or findex>/**init**.pyi).

To run tests on the Python interface, run:

```bash
bash ./scripts/test_python.sh
```

The `.whl` libraries can then be found in `target/wheels/`.

### Building the library for a different glibc

Go to the [build](build/glibc-2.17/) directory for an example on how to build for GLIBC 2.17

## Benchmarks

The benchmarks presented in this section are run on a Intel(R) Xeon(R) Platinum 8171M CPU @ 2.60GHz.

- [CoverCrypt classic](https://github.com/Cosmian/cover_crypt/blob/main/benches/BENCHMARKS_classic.md)
- [CoverCrypt post-quantum](https://github.com/Cosmian/cover_crypt/blob/main/benches/BENCHMARKS_hybridized.md)
- [Findex](https://github.com/Cosmian/findex/blob/develop/benches/BENCHMARKS.md)
- [FPE](./crates/fpe/benches/BENCHMARKS.md)

## Documentation

### CoverCrypt

A formal description and proof of the CoverCrypt scheme is given in [this paper](https://github.com/Cosmian/cover_crypt/blob/main/bib/CoverCrypt.pdf).
It also contains an interesting discussion about the implementation.

The developer documentation can be found on [doc.rs](https://docs.rs/cosmian_cover_crypt/latest/cosmian_cover_crypt/index.html)

### Findex

Findex technical documentation can be found [here](https://github.com/Cosmian/findex/blob/main/documentation/Findex.pdf).

The developer documentation can be found on [doc.rs](https://docs.rs/cosmian_findex/latest/cosmian_findex/index.html)

### Format Preserving Encryption

Findex technical documentation can be found [here](./crates/fpe/documentation/FPE.pdf).

## Releases

All releases can be found in the public URL [package.cosmian.com](https://package.cosmian.com).
