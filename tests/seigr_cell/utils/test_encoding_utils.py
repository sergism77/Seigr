import pytest
from src.seigr_cell.utils.encoding_utils import (
    serialize_metadata,
    deserialize_metadata,
    encode_with_password,
    decode_with_password,
)


### 🗃️ Serialization and Deserialization Tests ###

def test_serialize_deserialize_metadata():
    metadata = {
        "cell_id": str(uuid.uuid4()),  # Use a valid UUID
        "contributor_id": "contributor_1",
        "timestamp": "2025-01-06T13:39:09.151389+00:00",
        "version": "1.0",
        "data_hash": "hash123",
        "lineage_hash": "lineage123",
        "access_level": "public",
        "tags": ["tag1", "tag2"]
    }
    serialized = serialize_metadata(metadata)
    deserialized = deserialize_metadata(serialized)
    assert deserialized == metadata


def test_serialize_invalid_metadata():
    metadata = {"invalid_field": "value"}
    with pytest.raises(ValueError):
        serialize_metadata(metadata)


### 🔒 Encryption and Decryption Tests ###

def test_encode_decode_with_password():
    data = b"test_data"
    password = "secure_password"
    encrypted = encode_with_password(data, password)
    decrypted = decode_with_password(encrypted, password)
    assert decrypted == data


def test_decode_with_invalid_password():
    data = b"test_data"
    password = "secure_password"
    wrong_password = "wrong_password"
    encrypted = encode_with_password(data, password)
    with pytest.raises(ValueError):
        decode_with_password(encrypted, wrong_password)
