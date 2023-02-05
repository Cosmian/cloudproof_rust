<h1>Cosmian Anonymization Library</h1>

**WIP**

# FPE

NIST [mode specifications of FF1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf#page=19&zoom=100,0,0)
![](./documentation/FF1_NIST.png)

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

3. The benchmarks are available in [./benches/BENCHMARKS.md](./benches/BENCHMARKS.md)
