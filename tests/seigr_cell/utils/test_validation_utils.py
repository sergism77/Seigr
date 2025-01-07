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
import uuid
from datetime import datetime, timezone


### 🧪 Test validate_uuid ###

def test_validate_uuid_valid():
    """Test validate_uuid with a valid UUID."""
    valid_uuid = str(uuid.uuid4())
    assert validate_uuid(valid_uuid) is True


def test_validate_uuid_invalid():
    """Test validate_uuid with an invalid UUID."""
    invalid_uuid = "invalid-uuid"
    with pytest.raises(MetadataValidationError, match="Invalid UUID format"):
        validate_uuid(invalid_uuid)


### 🧪 Test validate_timestamp ###

def test_validate_timestamp_valid():
    """Test validate_timestamp with a valid ISO 8601 timestamp."""
    valid_timestamp = datetime.now(timezone.utc).isoformat()
    assert validate_timestamp(valid_timestamp) is True


def test_validate_timestamp_invalid():
    """Test validate_timestamp with an invalid timestamp."""
    invalid_timestamp = "2025-13-40T99:99:99"
    with pytest.raises(MetadataValidationError, match="Invalid timestamp format"):
        validate_timestamp(invalid_timestamp)


### 🧪 Test validate_access_policy ###

def test_validate_access_policy_valid():
    """Test validate_access_policy with valid data."""
    valid_policy = {
        "level": "public",
        "tags": ["initial", "test"]
    }
    assert validate_access_policy(valid_policy) is True


def test_validate_access_policy_invalid_level():
    """Test validate_access_policy with an invalid access level."""
    invalid_policy = {
        "level": "invalid_level",
        "tags": ["test"]
    }
    with pytest.raises(AccessPolicyValidationError, match="Invalid access level"):
        validate_access_policy(invalid_policy)


def test_validate_access_policy_invalid_tags():
    """Test validate_access_policy with invalid tags."""
    invalid_policy = {
        "level": "public",
        "tags": "not_a_list"
    }
    with pytest.raises(AccessPolicyValidationError, match="Tags must be a list of strings"):
        validate_access_policy(invalid_policy)


def test_validate_access_policy_not_a_dict():
    """Test validate_access_policy with a non-dictionary input."""
    with pytest.raises(AccessPolicyValidationError, match="Access policy must be a dictionary"):
        validate_access_policy(["not", "a", "dict"])


### 🧪 Test validate_metadata_schema ###

def test_validate_metadata_schema_valid():
    """Test validate_metadata_schema with valid metadata."""
    valid_metadata = {
        "cell_id": str(uuid.uuid4()),
        "contributor_id": "contributor_123",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0",
        "data_hash": "a3f5b2d7e2d7f2e1f7a3b5c6d7e8f9a0",
        "lineage_hash": "f3a7b2c5d8e9f1a0b2c3d4e5f6a7b8c9",
        "access_level": "public",
        "tags": ["initial", "test"]
    }
    assert validate_metadata_schema(valid_metadata) is True


def test_validate_metadata_schema_missing_field():
    """Test validate_metadata_schema with a missing required field."""
    invalid_metadata = {
        "cell_id": str(uuid.uuid4()),
        "contributor_id": "contributor_123",
        # Missing timestamp
        "version": "1.0",
        "data_hash": "a3f5b2d7e2d7f2e1f7a3b5c6d7e8f9a0",
        "lineage_hash": "f3a7b2c5d8e9f1a0b2c3d4e5f6a7b8c9",
        "access_level": "public",
        "tags": ["initial", "test"]
    }
    with pytest.raises(MetadataValidationError, match="Missing required metadata field: timestamp"):
        validate_metadata_schema(invalid_metadata)


def test_validate_metadata_schema_invalid_field():
    """Test validate_metadata_schema with an invalid field."""
    invalid_metadata = {
        "cell_id": "invalid_uuid",
        "contributor_id": "contributor_123",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0",
        "data_hash": "a3f5b2d7e2d7f2e1f7a3b5c6d7e8f9a0",
        "lineage_hash": "f3a7b2c5d8e9f1a0b2c3d4e5f6a7b8c9",
        "access_level": "public",
        "tags": ["initial", "test"]
    }
    with pytest.raises(MetadataValidationError, match="Invalid UUID format"):
        validate_metadata_schema(invalid_metadata)


def test_validate_metadata_schema_invalid_tags():
    """Test validate_metadata_schema with invalid tags."""
    invalid_metadata = {
        "cell_id": str(uuid.uuid4()),
        "contributor_id": "contributor_123",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0",
        "data_hash": "a3f5b2d7e2d7f2e1f7a3b5c6d7e8f9a0",
        "lineage_hash": "f3a7b2c5d8e9f1a0b2c3d4e5f6a7b8c9",
        "access_level": "public",
        "tags": "invalid_tags"
    }
    with pytest.raises(MetadataValidationError, match="tags must be a list of strings"):
        validate_metadata_schema(invalid_metadata)


### ✅ Main Test Runner ###
if __name__ == "__main__":
    pytest.main()
