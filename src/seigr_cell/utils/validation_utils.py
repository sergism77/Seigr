import uuid
from datetime import datetime
from src.logger.secure_logger import secure_logger  # Import Seigr's secure logger


# =======================
# Custom Exception Classes
# =======================
class MetadataValidationError(Exception):
    """Custom exception for metadata validation errors."""
    def __init__(self, message, field=None, value=None):
        super().__init__(message)
        self.field = field
        self.value = value


class AccessPolicyValidationError(Exception):
    """Custom exception for access policy validation errors."""
    def __init__(self, message, field=None, value=None):
        super().__init__(message)
        self.field = field
        self.value = value


# =======================
# Validation Functions
# =======================

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
        secure_logger.log_audit_event(
            severity=1,
            category="Validation",
            message=f"UUID {value} validated successfully.",
            sensitive=False,
        )
        return True
    except ValueError:
        secure_logger.log_audit_event(
            severity=3,
            category="Validation",
            message=f"Invalid UUID format: {value}",
            sensitive=True,
        )
        raise MetadataValidationError("Invalid UUID format.", field="UUID", value=value)


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
        secure_logger.log_audit_event(
            severity=1,
            category="Validation",
            message=f"Timestamp {value} validated successfully.",
            sensitive=False,
        )
        return True
    except ValueError:
        secure_logger.log_audit_event(
            severity=3,
            category="Validation",
            message=f"Invalid timestamp format: {value}",
            sensitive=True,
        )
        raise MetadataValidationError("Invalid timestamp format.", field="timestamp", value=value)


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
    valid_levels = ["public", "restricted", "private"]  # Centralize in config if needed
    try:
        if not isinstance(access_policy, dict):
            raise AccessPolicyValidationError("Access policy must be a dictionary.")

        level = access_policy.get("level", "public")
        if level not in valid_levels:
            raise AccessPolicyValidationError(
                f"Invalid access level: {level}. Must be one of {valid_levels}.",
                field="access_level",
                value=level,
            )

        tags = access_policy.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            raise AccessPolicyValidationError(
                "Tags must be a list of strings.", field="tags", value=tags
            )

        secure_logger.log_audit_event(
            severity=1,
            category="Validation",
            message="Access policy validated successfully.",
            sensitive=False,
        )
        return True
    except AccessPolicyValidationError as e:
        secure_logger.log_audit_event(
            severity=3,
            category="Validation",
            message=f"Access policy validation failed: {e}",
            sensitive=True,
        )
        raise


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
        "tags",
    ]

    try:
        for field in required_fields:
            if field not in metadata:
                raise MetadataValidationError(
                    f"Missing required metadata field: {field}",
                    field=field,
                )

        validate_uuid(metadata["cell_id"])
        validate_timestamp(metadata["timestamp"])

        if not isinstance(metadata["contributor_id"], str):
            raise MetadataValidationError("contributor_id must be a string.", field="contributor_id")
        if not isinstance(metadata["version"], str):
            raise MetadataValidationError("version must be a string.", field="version")
        if not isinstance(metadata["data_hash"], str):
            raise MetadataValidationError("data_hash must be a string.", field="data_hash")
        if not isinstance(metadata["lineage_hash"], str):
            raise MetadataValidationError("lineage_hash must be a string.", field="lineage_hash")

        if metadata["access_level"] not in ["public", "restricted", "private"]:
            raise MetadataValidationError(
                f"Invalid access_level: {metadata['access_level']}. Must be one of 'public', 'restricted', 'private'.",
                field="access_level",
                value=metadata["access_level"],
            )

        tags = metadata["tags"]
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            raise MetadataValidationError("tags must be a list of strings.", field="tags", value=tags)

        secure_logger.log_audit_event(
            severity=1,
            category="Validation",
            message="Metadata schema validated successfully.",
            sensitive=False,
        )
        return True
    except MetadataValidationError as e:
        secure_logger.log_audit_event(
            severity=3,
            category="Validation",
            message=f"Metadata validation failed: {e}",
            sensitive=True,
        )
        raise
