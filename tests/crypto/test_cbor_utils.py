import pytest
import os
from unittest.mock import MagicMock, patch
from src.crypto.cbor_utils import (
    encode_data,
    decode_data,
    transform_data,
    save_to_file,
    load_from_file,
)
from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData


### ✅ Fixture for Secure Logger Initialization ###
@pytest.fixture(autouse=True)
def initialize_secure_logger():
    """Ensure the SecureLogger instance is initialized before each test."""
    from src.crypto.secure_logging import _initialize_secure_logger
    _initialize_secure_logger()


### 🧪 Test Data Transformation ###
def test_transform_data():
    """Test transform_data function handles various data types correctly."""
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
    """Test successful CBOR encoding."""
    data = {"key": "value"}
    result = encode_data(data)
    assert isinstance(result, EncryptedData)
    assert result.ciphertext is not None


def test_encode_data_failure(mocker):
    """Test CBOR encoding failure."""
    mocker.patch('cbor2.dumps', side_effect=Exception("Mocked failure"))
    with pytest.raises(ValueError, match="CBOR encoding error occurred"):
        encode_data({"key": "value"})


### 🧪 Test CBOR Decoding ###
def test_decode_data():
    """Test successful CBOR decoding."""
    data = {"key": "value"}
    encrypted = encode_data(data)
    decoded = decode_data(encrypted)
    assert decoded == {"key": "value"}


def test_decode_invalid_cbor_data():
    """Test decoding malformed CBOR data raises ValueError."""
    invalid_data = EncryptedData(ciphertext=b'\x9f\x9f\x00')
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(invalid_data)


def test_decode_empty_ciphertext():
    """Test decoding empty ciphertext."""
    empty_encrypted_data = EncryptedData(ciphertext=b'')
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(empty_encrypted_data)


### 🧪 Test Malicious Payload Decoding ###
def test_decode_malicious_payload():
    """Test decoding a potentially malicious payload."""
    malicious_data = EncryptedData(ciphertext=b'\x00\x01\x02')
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(malicious_data)


### 🧪 Test Invalid EncryptedData Object ###
def test_invalid_encrypted_data_object():
    """Test decoding invalid EncryptedData object."""
    with pytest.raises(ValueError, match="Invalid EncryptedData object for decoding."):
        decode_data(None)


### 🧪 Test Secure Logging ###
def test_secure_logging_on_encode_decode(mocker):
    from src.crypto.secure_logging import _secure_logger_instance

    mock_logger = mocker.patch.object(
        _secure_logger_instance, 'log_audit_event', autospec=True
    )

    data = {"key": "value"}
    encrypted = encode_data(data)
    decode_data(encrypted)

    assert mock_logger.call_count >= 2

def test_secure_logging_on_error(mocker):
    from src.crypto.secure_logging import _secure_logger_instance

    mock_logger = mocker.patch.object(
        _secure_logger_instance, 'log_audit_event', autospec=True
    )

    invalid_data = EncryptedData(ciphertext=b'\x9f\x9f\x00')
    with pytest.raises(ValueError):
        decode_data(invalid_data)

    assert mock_logger.call_count > 0

### 🧪 Test File Operations ###
def test_save_and_load_from_file(tmp_path):
    """Test saving to and loading from a CBOR file."""
    file_path = tmp_path / "test_file.cbor"
    data = {"key": "value"}

    save_to_file(data, file_path)
    loaded_data = load_from_file(file_path)

    assert loaded_data == data


def test_save_to_file_failure(mocker, tmp_path):
    """Test failure during file save."""
    mocker.patch('builtins.open', side_effect=Exception("File error"))
    file_path = tmp_path / "test_file.cbor"
    with pytest.raises(Exception, match="File error"):
        save_to_file({"key": "value"}, file_path)


def test_load_from_file_failure(mocker, tmp_path):
    """Test failure during file load."""
    mocker.patch('builtins.open', side_effect=Exception("File error"))
    file_path = tmp_path / "test_file.cbor"
    with pytest.raises(Exception, match="File error"):
        load_from_file(file_path)


### 🧪 Test Edge Cases ###
def test_encode_empty_data():
    """Test encoding an empty dictionary."""
    test_data = {}

    encoded = encode_data(test_data)
    assert isinstance(encoded.ciphertext, bytes), "Encoded data should be in bytes format."

    decoded = decode_data(encoded)
    assert decoded == test_data, "Decoded data should match the original empty dictionary."


def test_encode_large_data():
    """Test encoding and decoding a large dataset."""
    large_data = {f"key_{i}": i for i in range(10000)}

    encoded = encode_data(large_data)
    decoded = decode_data(encoded)
    assert decoded == large_data
