import json
from typing import Any, Dict
from src.crypto.hypha_crypt import HyphaCrypt
from src.seigr_cell.utils.validation_utils import validate_metadata_schema
from src.logger.secure_logger import secure_logger  # Replace generic logger

### 🗃️ Serialization and Deserialization ###


def serialize_metadata(metadata: Dict[str, Any]) -> bytes:
    """
    Serializes metadata into a JSON-encoded binary format.

    Args:
        metadata (dict): Metadata dictionary to serialize.

    Returns:
        bytes: JSON-encoded binary data.

    Raises:
        ValueError: If serialization or validation fails.
    """
    try:
        validate_metadata_schema(metadata)
        serialized_data = json.dumps(metadata).encode("utf-8")
        secure_logger.log_audit_event(
            severity=1,
            category="Serialization",
            message="Metadata serialized successfully.",
            sensitive=False,
        )
        return serialized_data
    except Exception as e:
        secure_logger.log_audit_event(
            severity=4,
            category="Serialization",
            message=f"Failed to serialize metadata: {e}",
            sensitive=True,
        )
        raise ValueError("Serialization failed.") from e


def deserialize_metadata(serialized_data: bytes) -> Dict[str, Any]:
    """
    Deserializes binary metadata back into a Python dictionary.

    Args:
        serialized_data (bytes): JSON-encoded binary data.

    Returns:
        dict: Deserialized metadata dictionary.

    Raises:
        ValueError: If deserialization or validation fails.
    """
    try:
        metadata = json.loads(serialized_data.decode("utf-8"))
        validate_metadata_schema(metadata)
        secure_logger.log_audit_event(
            severity=1,
            category="Deserialization",
            message="Metadata deserialized successfully.",
            sensitive=False,
        )
        return metadata
    except Exception as e:
        secure_logger.log_audit_event(
            severity=4,
            category="Deserialization",
            message=f"Failed to deserialize metadata: {e}",
            sensitive=True,
        )
        raise ValueError("Deserialization failed.") from e


### 🔒 Encryption and Decryption with HyphaCrypt ###


def encode_with_password(data: bytes, password: str, segment_id: str = "default_segment") -> bytes:
    """
    Encrypts data with a password using HyphaCrypt.

    Args:
        data (bytes): Data to encrypt.
        password (str): Password for encryption.
        segment_id (str): Identifier for encryption context.

    Returns:
        bytes: Encrypted data.

    Raises:
        ValueError: If encryption fails.
    """
    try:
        hypha_crypt = HyphaCrypt(data=data, segment_id=segment_id)
        encryption_key = hypha_crypt.generate_encryption_key(password)
        encrypted_data = hypha_crypt.encrypt_data(encryption_key)
        secure_logger.log_audit_event(
            severity=1,
            category="Encryption",
            message=f"Data encrypted successfully for segment: {segment_id}.",
            sensitive=False,
        )
        return encrypted_data
    except Exception as e:
        secure_logger.log_audit_event(
            severity=4,
            category="Encryption",
            message=f"Failed to encrypt data for segment {segment_id}: {e}",
            sensitive=True,
        )
        raise ValueError("Encryption failed.") from e


def decode_with_password(
    encoded_data: bytes, password: str, segment_id: str = "default_segment"
) -> bytes:
    """
    Decrypts data with a password using HyphaCrypt.

    Args:
        encoded_data (bytes): Encrypted data.
        password (str): Password for decryption.
        segment_id (str): Identifier for encryption context.

    Returns:
        bytes: Decrypted data.

    Raises:
        ValueError: If decryption fails.
    """
    try:
        hypha_crypt = HyphaCrypt(data=b"", segment_id=segment_id)
        decryption_key = hypha_crypt.generate_encryption_key(password)
        decrypted_data = hypha_crypt.decrypt_data(encoded_data, decryption_key)
        secure_logger.log_audit_event(
            severity=1,
            category="Decryption",
            message=f"Data decrypted successfully for segment: {segment_id}.",
            sensitive=False,
        )
        return decrypted_data
    except Exception as e:
        secure_logger.log_audit_event(
            severity=4,
            category="Decryption",
            message=f"Failed to decrypt data for segment {segment_id}: {e}",
            sensitive=True,
        )
        raise ValueError("Decryption failed.") from e


### 🟡 Utility: Encoding Validation ###


def is_senary(data: bytes) -> bool:
    """
    Checks if the given data is encoded in a custom Seigr Senary format.

    Args:
        data (bytes): Data to check.

    Returns:
        bool: True if data is senary-encoded, False otherwise.
    """
    try:
        # Example logic: Check for Seigr-specific senary characteristics.
        decoded_data = data.decode("utf-8")
        is_valid = all(c in "012345" for c in decoded_data)
        secure_logger.log_audit_event(
            severity=1,
            category="Validation",
            message="Senary encoding validation completed.",
            sensitive=False,
        )
        return is_valid
    except Exception as e:
        secure_logger.log_audit_event(
            severity=4,
            category="Validation",
            message=f"Senary encoding validation failed: {e}",
            sensitive=True,
        )
        return False
