# Benchmarks

## Table of Contents

- [Benchmark Results](#benchmark-results)
    - [FPE](#fpe)

## Benchmark Results

### FPE

|                            | `encryption`             | `decryption`                     |
|:---------------------------|:-------------------------|:-------------------------------- |
| **`credit card`**          | `70.55 us` (✅ **1.00x**) | `76.67 us` (✅ **1.09x slower**)  |
| **`decimal_u64`**          | `49.11 us` (✅ **1.00x**) | `55.60 us` (❌ *1.13x slower*)    |
| **`decimal_big_uint`**     | `75.87 us` (✅ **1.00x**) | `82.40 us` (✅ **1.09x slower**)  |
| **`hexadecimal_u64`**      | `50.96 us` (✅ **1.00x**) | `57.58 us` (❌ *1.13x slower*)    |
| **`hexadecimal_big_uint`** | `80.96 us` (✅ **1.00x**) | `89.83 us` (✅ **1.11x slower**)  |
| **`float_64`**             | `73.29 us` (✅ **1.00x**) | `78.46 us` (✅ **1.07x slower**)  |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

