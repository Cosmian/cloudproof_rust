<h1>Cosmian Cloudproof Data Protection Library</h1>

This library provides multiple data protection techniques for use in a zero-trust environment. The techniques range from simple, less secure modifications of plaintext to quantum-resistant encryption for the best protection.

The primitives offered, from least to most secure, are:

- Aggregation: replaces data with a numerical interval
- Differential privacy: adds noise to numerical data
- Format preserving encryption: encryption that preserves the format of the plaintext
- Hashing: deterministic hashing of a value
- CoverCrypt: post-quantum encryption with embedded access policies

<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->

<!-- code_chunk_output -->

- [Format Preserving Encryption (FPE)](#-format-preserving-encryption-fpe)
  - [Implementation](#-implementation)
  - [Using FPE](#-using-fpe)
    - [Encrypting Text](#-encrypting-text)
      - [Encrypting and decrypting an alpha numeric text](#-encrypting-and-decrypting-an-alpha-numeric-text)
      - [Encrypting and decrypting a credit card number](#-encrypting-and-decrypting-a-credit-card-number)
      - [Encrypting and decrypting a Chinese text with spaces](#-encrypting-and-decrypting-a-chinese-text-with-spaces)
    - [Encrypting Integers](#-encrypting-integers)
    - [Encrypting Floats](#-encrypting-floats)
- [Benchmarks](#-benchmarks)
  - [Run quick start](#-run-quick-start)
  - [Run detailed report (Linux, MacOS)](#-run-detailed-report-linux-macos)

<!-- /code_chunk_output -->

# Format Preserving Encryption (FPE)

FPE aims to encrypt plaintext while retaining its format (alphabet). FPE-FF1 is a normalized algorithm that uses symmetric encryption, but it's not as fast or secure as standardized symmetric (or public key) encryption methods like AES or ChaCha. It should only be used where the format of the ciphertext container is constrained (e.g., a fixed database schema that cannot be changed).

## Implementation

The FPE implementation follows NIST specifications for FF1 (found in the [NIST SP 800-38G specification](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf#page=19&zoom=100,0,0)).

The code is based on the `cosmian_fpe` directory found on [GitHub](https://github.com/Cosmian/cosmian_fpe), which is based on `str4d/fpe`. The number of Feistel rounds has been increased to 18 following the recommendations of this [cryptanalysis paper](https://eprint.iacr.org/2020/1311.pdf).

The implementation also enforces the requirement that `radix^min_len > 1_000_000`. For the `Alphabet` and `Integer` FPE facilities, this requirement is met with the following parameters:

| radix | example alphabet    | min text len |
| ----- | ------------------- | ------------ |
| 2     | "01"                | 20           |
| 10    | "01234567890"       | 6            |
| 16    | "01234567890abcdef" | 5            |

## Using FPE

Cosmian FPE proposes 3 structures:

- `fpe::Alphabet` to encrypt text
- `fpe::Integer` to encrypt integers with various radixes
- `fpe::Float` to encrypt floating numbers

### Encrypting Text

The `fpe::Alphabet` structure provides the ability to encrypt a plaintext using an `alphabet`.
Characters of the plaintext that belong to the alphabet are encrypted while the others are left unchanged at their original location in the ciphertext.

An alphabet can be instantiated using the `Alphabet::instantiate()` method:

```rust
let hexadecimal_alphabet = Alphabet::instantiate("01234567890abcdef").unwrap();
```

There are multiple pre-defined alphabets available:

- `Alphabet::alpha()`
- `Alphabet::alpha_lower()`
- `Alphabet::alpha_upper()`
- `Alphabet::numeric()`
- `Alphabet::hexa_decimal()`
- `Alphabet::alpha_numeric()`
- `Alphabet::chinese()`
- `Alphabet::latin1sup()`
- `Alphabet::latin1sup_alphanum()`

These alphabets can easily be extended using the `extend_with` method

```rust
//0-9a-zA-Z
let mut alphabet = Alphabet::alphanumeric();
// add the space character
alphabet.extend_with(" ");
```

#### Encrypting and decrypting an alphanumeric text

```rust
let key = [0_u8; 32];
let tweak = b"unique tweak";

let alphabet = Alphabet::alpha_numeric(); //0-9a-zA-Z

let ciphertext = alphabet.encrypt(&key, tweak, "alphanumeric").unwrap();
assert_eq!("jraqSuFWZmdH", ciphertext);

let plaintext = alphabet.decrypt(&key, tweak, &ciphertext).unwrap();
assert_eq!("alphanumeric", plaintext);
```

#### Encrypting and decrypting a credit card number

```rust
let key = [0_u8; 32];
let tweak = b"unique tweak";

let alphabet = Alphabet::numeric(); //0-9

let ciphertext = alphabet
   .encrypt(&key, tweak, "1234-1234-1234-1234")
   .unwrap();
assert_eq!("1415-4650-5562-7272", ciphertext);

let plaintext = alphabet.decrypt(&key, tweak, &ciphertext).unwrap();
assert_eq!("1234-1234-1234-1234", plaintext);
```

_Note_: since the `-` character is not part of the alphabet it is preserved during encryption and decryption.

#### Encrypting and decrypting a Chinese text with spaces

```rust
let key = [0_u8; 32];
let tweak = b"unique tweak";

let mut alphabet = Alphabet::chinese();
// add the space character to the alphabet
alphabet.extend_with(" ");

let ciphertext = alphabet.encrypt(&key, tweak, "天地玄黄 宇宙洪荒").unwrap();
assert_eq!("儖濣鈍媺惐墷礿截媃", ciphertext);

let plaintext = alphabet.decrypt(&key, tweak, &ciphertext).unwrap();
assert_eq!("天地玄黄 宇宙洪荒", plaintext);
```

_Note_: since the space character was added to the alphabet, it is also encrypted.

### Encrypting Integers

The `fpe::Integer` structure offers the ability to encrypt integers with a radix between 2 (binary) and 16 (hexadecimal) and up to a maximum power of this radix.

To encrypt decimal integers up to u64::MAX, use:

```rust
let key = [0_u8; 32];
let tweak = b"unique tweak";

// decimal number with digits 0-9
let radix = 10_u32;
// the number of digits of the biggest number = radix^digits -1
// In this case 6 decimal digits -> 999_999
let digits = 6;

let itg = Integer::instantiate(radix, digits).unwrap();

let ciphertext = itg.encrypt(&key, tweak, 123_456_u64).unwrap();
assert_eq!(110_655_u64, ciphertext);

let plaintext = itg.decrypt(&key, tweak, ciphertext).unwrap();
assert_eq!(123_456_u64, plaintext);
```

There is also support for Big Unsigned Integers

```rust
let key = [0_u8; 32];
let tweak = b"unique tweak";

// decimal number with digits 0-9
let radix = 10_u32;
// the number of digits of the greatest number = radix^digits -1 = 10^20-1
let digits = 20;

// the value to encrypt: 10^17
let value = BigUint::from_str_radix("100000000000000000", radix).unwrap();

let itg = Integer::instantiate(radix, digits).unwrap();

let ciphertext = itg.encrypt_big(&key, tweak, &value).unwrap();
assert_eq!(
   BigUint::from_str_radix("65348521845006160218", radix).unwrap(),
   ciphertext
);

let plaintext = itg.decrypt_big(&key, tweak, &ciphertext).unwrap();
assert_eq!(
   BigUint::from_str_radix("100000000000000000", radix).unwrap(),
   plaintext
);
```

### Encrypting Floats

The `fpe::Float` structure provides support to encrypting floats of type `f64`:

```rust
let key = [0_u8; 32];
let tweak = b"unique tweak";

let flt = Float::instantiate().unwrap();
let ciphertext = flt.encrypt(&key, tweak, 123_456.789_f64).unwrap();
assert_eq!(1.170438892319619e91_f64, ciphertext);

let plaintext = flt.decrypt(&key, tweak, ciphertext).unwrap();
assert_eq!(123_456.789_f64, plaintext);
```

# Benchmarks

## Run quick start

Run `cargo bench` from the root directory

## Run detailed report (Linux, MacOS)

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
