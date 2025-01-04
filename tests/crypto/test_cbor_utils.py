import pytest

from src.crypto.cbor_utils import decode_data, encode_data, load_from_file, save_to_file
from src.crypto.secure_logging import SecureLogger
from src.seigr_protocol.compiled.audit_logging_pb2 import LogCategory, LogLevel
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData

# Initialize SecureLogger for audit events
secure_logger = SecureLogger()


def test_encode_and_decode_data():
    """Test encoding and decoding of data with audit logging for each step."""
    # Prepare test data with a variety of data types
    test_data = {
        "message": "Hello, Seigr!",
        "count": 42,
        "values": [1, 2, 3, 4, 5],
        "binary_data": b"\x00\x01\x02",
    }

    # Encode data and verify it is in bytes format
    encoded_data = encode_data(test_data)
    assert isinstance(
        encoded_data.ciphertext, bytes
    ), "Encoded data should be in bytes format."

    # Log encoding event
    secure_logger.log_audit_event(
        severity=LogLevel.LOG_LEVEL_DEBUG,
        category=LogCategory.LOG_CATEGORY_DATA_ACCESS,
        message="Data encoding successful for test data.",
        sensitive=False,
    )

    # Decode data and verify it matches the original test data
    decoded_data = decode_data(encoded_data)
    assert decoded_data == test_data, "Decoded data should match the original."

    # Log decoding event
    secure_logger.log_audit_event(
        severity=LogLevel.LOG_LEVEL_DEBUG,
        category=LogCategory.LOG_CATEGORY_DATA_ACCESS,
        message="Data decoding successful and matches original.",
        sensitive=False,
    )


def test_save_to_and_load_from_file(tmp_path):
    """Test saving data to a file and reloading it with verification and audit logging."""
    # Prepare test data to save and reload
    test_data = {
        "name": "Seigr",
        "id": 123,
        "flags": [True, False, True],
        "binary_data": b"\x00\x01\x02",
    }

    # Define file path in the temporary directory
    file_path = tmp_path / "test_data.cbor"

    # Save to file and log event
    save_to_file(test_data, str(file_path))
    secure_logger.log_audit_event(
        severity=LogLevel.LOG_LEVEL_INFO,
        category=LogCategory.LOG_CATEGORY_SYSTEM_OPERATION,
        message=f"Data saved to file at {file_path}.",
        sensitive=False,
    )

    # Load data from file and verify it matches the original test data
    loaded_data = load_from_file(str(file_path))
    assert loaded_data == test_data, "Loaded data should match the saved data."

    # Log load event
    secure_logger.log_audit_event(
        severity=LogLevel.LOG_LEVEL_INFO,
        category=LogCategory.LOG_CATEGORY_SYSTEM_OPERATION,
        message="Data successfully loaded from file and verified.",
        sensitive=False,
    )


def test_encode_data_with_invalid_types():
    """Test encoding of data with an unsupported type, expecting a TypeError."""
    # Attempt to encode data with an invalid type (set), expecting a TypeError
    with pytest.raises(TypeError, match="Unsupported data type"):
        encode_data({"invalid_type": set([1, 2, 3])})

    # Log invalid encoding attempt
    secure_logger.log_audit_event(
        severity=LogLevel.LOG_LEVEL_WARN,
        category=LogCategory.LOG_CATEGORY_ERROR_EVENT,
        message="Attempted to encode data with an unsupported type (set).",
        sensitive=False,
    )


def test_decode_invalid_cbor_data():
    """Test decoding of a deliberately malformed CBOR byte sequence, expecting ValueError."""
    # Use a deliberately malformed CBOR byte sequence to ensure it triggers CBORDecodeError
    invalid_encrypted_data = EncryptedData(
        ciphertext=b"\x9f\x9f\x00"
    )  # Truncated CBOR array

    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(invalid_encrypted_data)

    # Log decoding error event
    secure_logger.log_audit_event(
        severity=LogLevel.LOG_LEVEL_ERROR,
        category=LogCategory.LOG_CATEGORY_ERROR_EVENT,
        message="CBOR decoding failed due to invalid byte sequence.",
        sensitive=False,
    )
