#!/bin/sh

set -e

# Usage: bash benches.sh

cargo criterion --message-format=json | criterion-table >benches/BENCHMARKS.md
