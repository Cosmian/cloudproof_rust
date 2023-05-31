#!/bin/sh
set -eux

test_python_interface() {
    # The name of the crate should be given as first argument.
    crate_dir="crates/$1"

    # Build and install dependencies
    pip install -r "$crate_dir/python/requirements.txt"
    rm -f ./target/wheels/*.whl
    maturin build -m "$crate_dir/Cargo.toml" --release --features python
    pip install --force-reinstall ./target/wheels/*.whl

    test_file="$crate_dir/python/tests/$1_test.py"

    # Test typing
    mypy "$test_file"

    # Unit tests
    python "$test_file"
}

# Setup python virtual environment
venv_dir="$(pwd)/target/venv"
rm -rf "$venv_dir"
mkdir -p "$venv_dir"
python3 -m venv "$venv_dir"

export PATH="$venv_dir/bin:$PATH"

# Tests required crates
test_crate=${1:-""}
if [ -z "$test_crate" ]; then
    test_python_interface findex
    test_python_interface cover_crypt
    test_python_interface fpe
    test_python_interface anonymization
elif [ "$test_crate" = "findex" ]; then
    test_python_interface findex
elif [ "$test_crate" = "cover_crypt" ]; then
    test_python_interface cover_crypt
elif [ "$test_crate" = "fpe" ]; then
    test_python_interface fpe
elif [ "$test_crate" = "anonymization" ]; then
    test_python_interface anonymization
else
    echo "No project named $test_crate"
    exit 1
fi
