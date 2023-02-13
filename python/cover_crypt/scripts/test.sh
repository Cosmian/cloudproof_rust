#!/bin/sh
set -eux

pip install -r python/cover_crypt/requirements.txt

rm -f target/wheels/*.whl
maturin build --release --features python,cover_crypt
pip install --force-reinstall target/wheels/*.whl

# Test typing
mypy python/cover_crypt/scripts/test_cover_crypt.py

# Unit tests
python3 python/cover_crypt/scripts/test_cover_crypt.py
