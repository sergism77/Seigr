# src/seigr_cell/utils/validation_utils.py

import re
import uuid
from datetime import datetime, timezone


class MetadataValidationError(Exception):
    """Custom exception for metadata validation errors."""
    pass


class AccessPolicyValidationError(Exception):
    """Custom exception for access policy validation errors."""
    pass


### 🛡️ Validation Functions ###

def validate_uuid(value: str) -> bool:
    """
    Validate if a given string is a valid UUID.

    Args:
        value (str): The UUID string to validate.

    Returns:
        bool: True if valid UUID, False otherwise.

    Raises:
        MetadataValidationError: If UUID is invalid.
    """
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        raise MetadataValidationError(f"Invalid UUID format: {value}")


def validate_timestamp(value: str) -> bool:
    """
    Validate if a timestamp follows ISO 8601 format.

    Args:
        value (str): Timestamp string.

    Returns:
        bool: True if valid ISO 8601 format, False otherwise.

    Raises:
        MetadataValidationError: If timestamp is invalid.
    """
    try:
        datetime.fromisoformat(value)
        return True
    except ValueError:
        raise MetadataValidationError(f"Invalid timestamp format: {value}")


def validate_access_policy(access_policy: dict) -> bool:
    """
    Validate access policy structure and values.

    Args:
        access_policy (dict): Access policy dictionary.

    Returns:
        bool: True if valid access policy, False otherwise.

    Raises:
        AccessPolicyValidationError: If access policy is invalid.
    """
    if not isinstance(access_policy, dict):
        raise AccessPolicyValidationError("Access policy must be a dictionary.")
    
    valid_levels = ["public", "restricted", "private"]
    level = access_policy.get("level", "public")
    if level not in valid_levels:
        raise AccessPolicyValidationError(
            f"Invalid access level: {level}. Must be one of {valid_levels}."
        )

    tags = access_policy.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        raise AccessPolicyValidationError("Tags must be a list of strings.")

    return True


def validate_metadata_schema(metadata: dict) -> bool:
    """
    Validate Seigr Cell metadata schema.

    Args:
        metadata (dict): Metadata dictionary to validate.

    Returns:
        bool: True if valid schema, False otherwise.

    Raises:
        MetadataValidationError: If metadata validation fails.
    """
    required_fields = [
        "cell_id",
        "contributor_id",
        "timestamp",
        "version",
        "data_hash",
        "lineage_hash",
        "access_level",
        "tags"
    ]

    # Check required fields
    for field in required_fields:
        if field not in metadata:
            raise MetadataValidationError(f"Missing required metadata field: {field}")

    # Validate individual fields
    validate_uuid(metadata["cell_id"])
    validate_timestamp(metadata["timestamp"])

    if not isinstance(metadata["contributor_id"], str):
        raise MetadataValidationError("contributor_id must be a string.")
    if not isinstance(metadata["version"], str):
        raise MetadataValidationError("version must be a string.")
    if not isinstance(metadata["data_hash"], str):
        raise MetadataValidationError("data_hash must be a string.")
    if not isinstance(metadata["lineage_hash"], str):
        raise MetadataValidationError("lineage_hash must be a string.")
    
    access_level = metadata["access_level"]
    if access_level not in ["public", "restricted", "private"]:
        raise MetadataValidationError(
            f"Invalid access_level: {access_level}. Must be 'public', 'restricted', or 'private'."
        )
    
    tags = metadata["tags"]
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        raise MetadataValidationError("tags must be a list of strings.")

    return True
