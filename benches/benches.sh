# Usage: bash bench.sh

#!/bin/sh

set -e

cargo criterion  --message-format=json | criterion-table >benches/BENCHMARKS.md

