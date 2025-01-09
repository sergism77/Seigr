# tests/seigr_cell/utils/test_encoding_utils.py

import pytest
from src.seigr_cell.utils.encoding_utils import (
    serialize_metadata,
    deserialize_metadata,
    encode_with_password,
    decode_with_password,
)


def test_serialize_metadata():
    metadata = {
        "cell_id": "123e4567-e89b-12d3-a456-426614174000",  # Valid UUID
        "contributor_id": "default_segment",
        "timestamp": "2025-01-09T13:28:53.942332+00:00",
        "version": "1.0",
        "data_hash": "abcd1234",
        "lineage_hash": "efgh5678",
        "access_level": "public",
        "tags": ["test"]
    }
    serialized = serialize_metadata(metadata)
    assert isinstance(serialized, bytes)
    assert b'"cell_id": "123e4567-e89b-12d3-a456-426614174000"' in serialized



def test_deserialize_metadata():
    serialized = b'{"cell_id": "123e4567-e89b-12d3-a456-426614174000", "contributor_id": "default_segment", "timestamp": "2025-01-09T13:28:53.942332+00:00", "version": "1.0", "data_hash": "abcd1234", "lineage_hash": "efgh5678", "access_level": "public", "tags": ["test"]}'
    metadata = deserialize_metadata(serialized)
    assert isinstance(metadata, dict)
    assert metadata["cell_id"] == "123e4567-e89b-12d3-a456-426614174000"


def test_encode_with_password():
    data = b"secret_data"
    password = "strong_password"
    encoded = encode_with_password(data, password)
    assert isinstance(encoded, bytes)
    assert encoded != data  # Ensure data is encrypted


def test_decode_with_password():
    data = b"secret_data"
    password = "strong_password"
    segment_id = "test_segment"

    # Ensure consistent encode-decode parameters
    encoded = encode_with_password(data, password, segment_id)
    decoded = decode_with_password(encoded, password, segment_id)  # Match segment_id

    assert decoded == data, "Decoded data does not match original"
