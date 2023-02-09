<<<<<<< HEAD
=======
# Usage: bash benches.sh

>>>>>>> c8dba97 (feat: get callback errors from Findex)
#!/bin/sh

set -e

<<<<<<< HEAD
# Usage: bash benches.sh

cargo bench --message-format=json | criterion-table >benches/BENCHMARKS.md

sed -i "s/❌ //g" benches/BENCHMARKS*.md
# sed -i "s/✅ //g" benches/BENCHMARKS*.md
=======
cargo bench  --message-format=json | criterion-table >benches/BENCHMARKS.md

sed -i "s/❌ //g" benches/BENCHMARKS*.md
# sed -i "s/✅ //g" benches/BENCHMARKS*.md
>>>>>>> c8dba97 (feat: get callback errors from Findex)
