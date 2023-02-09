<<<<<<< HEAD
=======
# Usage: bash bench.sh

>>>>>>> c8dba97 (feat: get callback errors from Findex)
#!/bin/sh

set -e

<<<<<<< HEAD
# Usage: bash benches.sh

cargo criterion --message-format=json | criterion-table >benches/BENCHMARKS.md
=======
cargo criterion  --message-format=json | criterion-table >benches/BENCHMARKS.md

>>>>>>> c8dba97 (feat: get callback errors from Findex)
