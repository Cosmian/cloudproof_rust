#!/bin/sh
set -eux

pip install -r python/requirements.txt
rm -f ../target/wheels/*.whl

maturin build --release --features python
pip install --force-reinstall ../target/wheels/*findex*.whl

# Test typing
mypy python/tests/findex_test.py
# Unit tests
python3 python/tests/findex_test.py
