#!/bin/sh
set -eux

# The name of the crate should be given as first argument.
crate_dir=$1

# Setup python virtual environment
venv_dir=$(pwd)/target/venv
mkdir -p "$venv_dir"
python3 -m venv "$venv_dir"
export PATH="$venv_dir/bin:$PATH"

# Build and install dependencies
pip install -r "crates/$crate_dir/python/requirements.txt"
rm -f ./target/wheels/*.whl
maturin build -m "crates/$crate_dir/Cargo.toml" --release --features python
pip install --force-reinstall ./target/wheels/*.whl

# Test typing
mypy "crates/$crate_dir/python/tests/$1_test.py"

# Unit tests
python "crates/$crate_dir/python/tests/$1_test.py"
