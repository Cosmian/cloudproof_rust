#!/bin/sh
set -eux

pip install -r python/requirements.txt
rm -f ../target/wheels/*.whl

maturin build --release --features python
pip install --force-reinstall ../target/wheels/*cover_crypt*.whl

# Test typing
mypy python/tests/cover_crypt_test.py
# Unit tests
python3 python/tests/cover_crypt_test.py
