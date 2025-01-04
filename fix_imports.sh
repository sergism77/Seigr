#!/bin/bash

# Adjust imports in compiled Protobuf files
find src/seigr_protocol/compiled -name "*.py" -exec sed -i 's/^import \([a-zA-Z_]*_pb2\)/from . import \1/' {} +

echo "✅ Imports in compiled Protobuf files have been fixed."
