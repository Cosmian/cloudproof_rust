#!/bin/sh

set -e

# Usage: From `crates/fpe` folder, run `bash ./benches/benches.sh`

cargo criterion -p cloudproof_fpe --message-format=json | criterion-table >benches/BENCHMARKS.md

sed -i "s/❌ //g" benches/BENCHMARKS*.md
# sed -i "s/✅ //g" benches/BENCHMARKS*.md
