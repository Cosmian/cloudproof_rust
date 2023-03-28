use cloudproof_fpe::core::{Alphabet, Float, Integer, KEY_LENGTH};
use criterion::{criterion_group, criterion_main, Criterion};
use num_bigint::BigUint;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Generate a random key using a cryptographically
/// secure random number generator that is suitable for use with FPE
#[must_use]
pub fn random_key() -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut key = [0_u8; KEY_LENGTH];
    rng.fill_bytes(&mut key);
    key
}

fn bench_fpe_credit_card(c: &mut Criterion) {
    let credit_card = "1234-1234-1234-1234";
    let key = random_key();
    let alphabet = Alphabet::numeric();

    c.bench_function("FPE/encryption/credit card", |b| {
        b.iter(|| {
            alphabet.encrypt(&key, &[], credit_card).unwrap();
        });
    });

    let ciphertext = alphabet.encrypt(&key, &[], credit_card).unwrap();
    c.bench_function("FPE/decryption/credit card", |b| {
        b.iter(|| {
            alphabet.decrypt(&key, &[], ciphertext.as_str()).unwrap();
        });
    });
}

fn bench_fpe_decimal(c: &mut Criterion) {
    let key = random_key();

    let decimal = Integer::instantiate(10, 9).unwrap();
    let num = 123_456_789_u64;
    c.bench_function("FPE/encryption/decimal_u64", |b| {
        b.iter(|| {
            decimal.encrypt(&key, &[], num).unwrap();
        });
    });
    let ciphertext = decimal.encrypt(&key, &[], num).unwrap();
    c.bench_function("FPE/decryption/decimal_u64", |b| {
        b.iter(|| {
            decimal.decrypt(&key, &[], ciphertext).unwrap();
        });
    });

    let decimal = Integer::instantiate(10, 20).unwrap();
    let num = BigUint::from(10_u32).pow(19_u32);
    c.bench_function("FPE/encryption/decimal_big_uint", |b| {
        b.iter(|| {
            decimal.encrypt_big(&key, &[], &num).unwrap();
        });
    });

    let ciphertext = decimal.encrypt_big(&key, &[], &num).unwrap();
    c.bench_function("FPE/decryption/decimal_big_uint", |b| {
        b.iter(|| {
            decimal.decrypt_big(&key, &[], &ciphertext).unwrap();
        });
    });
}

fn bench_fpe_hexadecimal(c: &mut Criterion) {
    let key = random_key();

    let hexadecimal = Integer::instantiate(16, 9).unwrap();
    let num = 123_456_789_u64;
    c.bench_function("FPE/encryption/hexadecimal_u64", |b| {
        b.iter(|| {
            hexadecimal.encrypt(&key, &[], num).unwrap();
        });
    });
    let ciphertext = hexadecimal.encrypt(&key, &[], num).unwrap();
    c.bench_function("FPE/decryption/hexadecimal_u64", |b| {
        b.iter(|| {
            hexadecimal.decrypt(&key, &[], ciphertext).unwrap();
        });
    });

    let hexadecimal = Integer::instantiate(16, 20).unwrap();
    let num = BigUint::from(10_u32).pow(19_u32);
    c.bench_function("FPE/encryption/hexadecimal_big_uint", |b| {
        b.iter(|| {
            hexadecimal.encrypt_big(&key, &[], &num).unwrap();
        });
    });

    let ciphertext = hexadecimal.encrypt_big(&key, &[], &num).unwrap();
    c.bench_function("FPE/decryption/hexadecimal_big_uint", |b| {
        b.iter(|| {
            hexadecimal.decrypt_big(&key, &[], &ciphertext).unwrap();
        });
    });
}

fn bench_fpe_float(c: &mut Criterion) {
    let key = random_key();
    let float_value = 123_456.789_0_f64;
    let fpe_float = Float::instantiate().unwrap();

    c.bench_function("FPE/encryption/float_64", |b| {
        b.iter(|| {
            fpe_float.encrypt(&key, &[], float_value).unwrap();
        });
    });

    let ciphertext = fpe_float.encrypt(&key, &[], float_value).unwrap();
    c.bench_function("FPE/decryption/float_64", |b| {
        b.iter(|| {
            fpe_float.decrypt(&key, &[], ciphertext).unwrap();
        });
    });
}

criterion_group!(
    name = benches_fpe;
    config = Criterion::default().sample_size(10000);
    targets =
        bench_fpe_credit_card,
        bench_fpe_decimal,
        bench_fpe_hexadecimal,
        bench_fpe_float
);

criterion_main!(benches_fpe);
