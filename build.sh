#!/bin/bash

echo "OFFLINE=$OFFLINE"

set -e

# Cleanup lib (preserve vendored qontrol)
rm -f ./lib/libreckless.*
rm -rf ./lib/include
mkdir -p ./lib/include

# Build reckless Rust crate
cd reckless
if [ -z "$OFFLINE" ]; then
    OFFLINE=false
fi
if [ "$OFFLINE" = false ]; then
    cargo build --release
else
    cargo build --release --offline
fi

cd ..

# Copy CXX bridge generated headers into ./lib/include/
cp -L ./reckless/target/cxxbridge/reckless/src/lib.rs.h ./lib/include/reckless.h
cp -L ./reckless/target/cxxbridge/rust/cxx.h ./lib/include/cxx.h

# Copy static library into ./lib/
cp ./reckless/target/release/libreckless.a ./lib/libreckless.a
cp ./reckless/target/release/libreckless.rlib ./lib/libreckless.rlib
cp ./reckless/target/release/libreckless.d ./lib/libreckless.d
