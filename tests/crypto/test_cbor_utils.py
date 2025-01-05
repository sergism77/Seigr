import pytest
from unittest.mock import MagicMock, patch, call
from src.crypto.cbor_utils import (
    encode_data,
    decode_data,
    transform_data,
    save_to_file,
    load_from_file,
)
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData
from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from src.crypto.secure_logging import _secure_logger_instance

# Initialize _secure_logger_instance if it's not already initialized
if _secure_logger_instance is None:
    _secure_logger_instance = MagicMock()


### ✅ Fixture for Secure Logger Initialization ###
@pytest.fixture(autouse=True)
def mock_secure_logger(mocker):
    """
    Automatically mock the secure logger for every test.
    """
    if not isinstance(_secure_logger_instance.log_audit_event, MagicMock):
        mock_logger = mocker.patch.object(
            _secure_logger_instance,
            'log_audit_event',
            autospec=True
        )
    else:
        mock_logger = _secure_logger_instance.log_audit_event
    return mock_logger


### 🧪 Test Data Transformation ###
def test_transform_data():
    """
    Test transform_data handles various data types correctly.
    """
    assert transform_data(b"bytes") == b"bytes"
    assert transform_data({"key": "value"}) == {"key": "value"}
    assert transform_data([1, 2, 3]) == [1, 2, 3]
    assert transform_data("string") == "string"
    assert transform_data(123) == 123
    assert transform_data(None) is None

    with pytest.raises(TypeError, match="Unsupported data type: object"):
        transform_data(object())


### 🧪 Test CBOR Encoding ###
def test_encode_data():
    """
    Test successful CBOR encoding.
    """
    data = {"key": "value"}
    result = encode_data(data)
    assert isinstance(result, EncryptedData)
    assert result.ciphertext is not None


def test_encode_data_failure(mocker):
    """
    Test CBOR encoding failure.
    """
    mocker.patch('cbor2.dumps', side_effect=Exception("Mocked failure"))
    with pytest.raises(ValueError, match="CBOR encoding error occurred"):
        encode_data({"key": "value"})


### 🧪 Test CBOR Decoding ###
def test_decode_data():
    """
    Test successful CBOR decoding.
    """
    data = {"key": "value"}
    encrypted = encode_data(data)
    decoded = decode_data(encrypted)
    assert decoded == {"key": "value"}


def test_decode_invalid_cbor_data():
    """
    Test decoding malformed CBOR data raises ValueError.
    """
    invalid_data = EncryptedData(ciphertext=b'\x9f\x9f\x00')
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(invalid_data)


def test_decode_empty_ciphertext():
    """
    Test decoding empty ciphertext raises ValueError.
    """
    empty_encrypted_data = EncryptedData(ciphertext=b'')
    with pytest.raises(ValueError, match="Invalid EncryptedData object for decoding"):
        decode_data(empty_encrypted_data)


def test_decode_malicious_payload():
    """
    Test decoding a malicious payload should raise ValueError.
    """
    malicious_data = EncryptedData(ciphertext=b'\x9f\x9f\x00')
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(malicious_data)


def test_invalid_encrypted_data_object():
    """
    Test decoding an invalid EncryptedData object raises ValueError.
    """
    with pytest.raises(ValueError, match="Invalid EncryptedData object for decoding"):
        decode_data(None)


### 🧪 Test Secure Logging ###
def test_secure_logging_on_encode_decode(mock_secure_logger):
    """
    Test secure logging during encode and decode operations.
    """
    data = {"key": "value"}
    encrypted = encode_data(data)
    decode_data(encrypted)

    # Ensure log_audit_event was called twice: once on encode, once on decode
    assert mock_secure_logger.call_count >= 2
    mock_secure_logger.assert_has_calls([
        call(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Encode",
            message="Data successfully encoded to CBOR format",
            sensitive=False,
            use_senary=False
        ),
        call(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Decode",
            message="Data successfully decoded from CBOR format",
            sensitive=False,
            use_senary=False
        )
    ])


def test_secure_logging_on_error(mock_secure_logger):
    """
    Test secure logging during decode error scenarios.
    """
    invalid_data = EncryptedData(ciphertext=b'\x9f\x9f\x00')
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(invalid_data)

    assert mock_secure_logger.call_count > 0
    mock_secure_logger.assert_any_call(
        severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
        category="Alert",
        message="CBOR decode error",
        sensitive=False,
        use_senary=False
    )


### 🧪 Test File Operations ###
def test_save_and_load_from_file(tmp_path):
    """
    Test saving and loading data from a CBOR file.
    """
    file_path = tmp_path / "test_file.cbor"
    data = {"key": "value"}

    save_to_file(data, file_path)
    loaded_data = load_from_file(file_path)

    assert loaded_data == data


def test_save_to_file_failure(mocker, tmp_path):
    """
    Test failure during file save.
    """
    mocker.patch('builtins.open', side_effect=IOError("Failed to save file"))
    file_path = tmp_path / "test_file.cbor"
    with pytest.raises(IOError, match="Failed to save file"):
        save_to_file({"key": "value"}, file_path)


def test_load_from_file_failure(mocker, tmp_path):
    """
    Test failure during file load.
    """
    mocker.patch('builtins.open', side_effect=IOError("Failed to load file"))
    file_path = tmp_path / "test_file.cbor"
    with pytest.raises(IOError, match="Failed to load file"):
        load_from_file(file_path)


### 🧪 Test Edge Cases ###
def test_encode_empty_data():
    """
    Test encoding and decoding an empty dictionary.
    """
    test_data = {}

    encoded = encode_data(test_data)
    assert isinstance(encoded.ciphertext, bytes)

    decoded = decode_data(encoded)
    assert decoded == test_data


def test_encode_large_data():
    """
    Test encoding and decoding a large dataset.
    """
    large_data = {f"key_{i}": i for i in range(10000)}

    encoded = encode_data(large_data)
    decoded = decode_data(encoded)
    assert decoded == large_data
