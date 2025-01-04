#!/bin/bash

# Ensure script stops on errors
set -e

# Define paths
PROTO_SRC="src/seigr_protocol"
PROTO_OUT="src/seigr_protocol/compiled"

# Clean previous compilation artifacts
rm -rf "$PROTO_OUT"/*
rm -rf ~/.pylint.d

# Move to src directory for consistent path resolution
pushd src/seigr_protocol > /dev/null

# Compile Protobuf Files
protoc \
  --proto_path=. \
  --python_out=compiled \
  $(find . -name "*.proto")

# Return to the original directory
popd > /dev/null

# Verify Successful Compilation
echo "✅ Protobuf files compiled successfully."

# Clear Pylint Cache
rm -rf ~/.pylint.d
