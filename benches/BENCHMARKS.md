# Benchmarks

## Table of Contents

- [Benchmark Results](#benchmark-results)
    - [FPE](#fpe)

## Benchmark Results

### FPE

|                            | `encryption`             | `decryption`                      |
|:---------------------------|:-------------------------|:--------------------------------- |
| **`credit card`**          | `69.01 us` (✅ **1.00x**) | `77.26 us` (❌ *1.12x slower*)     |
| **`decimal_u64`**          | `47.26 us` (✅ **1.00x**) | `56.83 us` (❌ *1.20x slower*)     |
| **`decimal_big_uint`**     | `83.62 us` (✅ **1.00x**) | `88.18 us` (✅ **1.05x slower**)   |
| **`hexadecimal_u64`**      | `50.56 us` (✅ **1.00x**) | `58.58 us` (❌ *1.16x slower*)     |
| **`hexadecimal_big_uint`** | `83.22 us` (✅ **1.00x**) | `101.75 us` (❌ *1.22x slower*)    |
| **`credit card #2`**       | `79.51 us` (✅ **1.00x**) | `85.41 us` (✅ **1.07x slower**)   |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

