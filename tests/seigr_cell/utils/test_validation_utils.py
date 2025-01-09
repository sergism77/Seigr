# tests/seigr_cell/utils/test_validation_utils.py

import pytest
from src.seigr_cell.utils.validation_utils import (
    validate_uuid,
    validate_timestamp,
    validate_access_policy,
    validate_metadata_schema,
    MetadataValidationError,
    AccessPolicyValidationError,
)


def test_validate_uuid():
    valid_uuid = "123e4567-e89b-12d3-a456-426614174000"
    invalid_uuid = "not-a-valid-uuid"

    assert validate_uuid(valid_uuid)

    with pytest.raises(MetadataValidationError):
        validate_uuid(invalid_uuid)


def test_validate_timestamp():
    valid_timestamp = "2023-01-01T00:00:00+00:00"
    invalid_timestamp = "invalid-timestamp"

    assert validate_timestamp(valid_timestamp)

    with pytest.raises(MetadataValidationError):
        validate_timestamp(invalid_timestamp)


def test_validate_access_policy():
    valid_policy = {"level": "public", "tags": ["tag1", "tag2"]}
    invalid_policy = {"level": "unknown", "tags": ["tag1", 123]}

    assert validate_access_policy(valid_policy)

    with pytest.raises(AccessPolicyValidationError):
        validate_access_policy(invalid_policy)


def test_validate_metadata_schema():
    valid_metadata = {
        "cell_id": "123e4567-e89b-12d3-a456-426614174000",
        "contributor_id": "segment123",
        "timestamp": "2023-01-01T00:00:00+00:00",
        "version": "1.0",
        "data_hash": "abc123",
        "lineage_hash": "def456",
        "access_level": "public",
        "tags": ["tag1"],
    }
    invalid_metadata = valid_metadata.copy()
    del invalid_metadata["cell_id"]

    assert validate_metadata_schema(valid_metadata)

    with pytest.raises(MetadataValidationError):
        validate_metadata_schema(invalid_metadata)
