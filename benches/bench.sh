# Usage: bash benches.sh

#!/bin/sh

set -e

cargo bench  --message-format=json | criterion-table >benches/BENCHMARKS.md

sed -i "s/❌ //g" benches/BENCHMARKS*.md
# sed -i "s/✅ //g" benches/BENCHMARKS*.md