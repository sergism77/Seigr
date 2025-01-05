import pytest
from unittest.mock import MagicMock, patch
from src.crypto.cbor_utils import (
    encode_data,
    decode_data,
    transform_data,
    save_to_file,
    load_from_file,
)
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData


# ✅ Fixture for Secure Logger Initialization ###
@pytest.fixture
def mock_secure_logger():
    with patch('src.crypto.secure_logging._secure_logger_instance') as mock_logger:
        mock_logger.log_audit_event = MagicMock()
        yield mock_logger


# 🧪 Test Data Transformation
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


# 📝 Test CBOR Encoding
def test_encode_data(mock_secure_logger):
    """Test successful CBOR encoding."""
    data = {"key": "value"}
    result = encode_data(data)
    assert isinstance(result, EncryptedData)
    assert result.ciphertext is not None
    
    # Verify the log call
    mock_secure_logger.log_audit_event.assert_called_with(
        severity=2,
        category="Encode",
        message="Data successfully encoded to CBOR format",
        sensitive=False,
        use_senary=False
    )


# 🚨 Test Encoding Failure
def test_encode_data_failure(mock_secure_logger):
    """Test CBOR encoding failure."""
    with patch('cbor2.dumps', side_effect=Exception("Mocked failure")):
        with pytest.raises(ValueError, match="CBOR encoding error occurred"):
            encode_data({"key": "value"})
    mock_secure_logger.log_audit_event.assert_called_with(
        severity=3,
        category="Encode",
        message="CBOR encoding error occurred",
        sensitive=False,
        use_senary=False
    )


# 📝 Test CBOR Decoding
def test_decode_data(mock_secure_logger):
    """Test successful CBOR decoding."""
    data = {"key": "value"}
    encrypted = encode_data(data)
    decoded = decode_data(encrypted)
    assert decoded == {"key": "value"}
    
    # Verify the log call
    mock_secure_logger.log_audit_event.assert_any_call(
        severity=2,
        category="Decode",
        message="Data successfully decoded from CBOR format",
        sensitive=False,
        use_senary=False
    )


# 🚨 Test Invalid CBOR Data
def test_decode_invalid_cbor_data(mock_secure_logger):
    """Test decoding malformed CBOR data raises ValueError."""
    invalid_data = EncryptedData(ciphertext=b'\x9f\x9f\x00')
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(invalid_data)
    
    # Verify the log call
    mock_secure_logger.log_audit_event.assert_any_call(
        severity=3,
        category="Alert",
        message="CBOR decode error: premature end of stream",
        sensitive=False,
        use_senary=False
    )


# 🚨 Test Empty Ciphertext Decoding
def test_decode_empty_ciphertext():
    """Test decoding empty ciphertext."""
    empty_encrypted_data = EncryptedData(ciphertext=b'')
    with pytest.raises(ValueError, match="Invalid EncryptedData object for decoding"):
        decode_data(empty_encrypted_data)


# 🚨 Test Secure Logging on Error
def test_secure_logging_on_error(mock_secure_logger):
    """Test secure logging during decode error scenarios."""
    invalid_data = EncryptedData(ciphertext=b'\x9f\x9f\x00')
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(invalid_data)
    
    # Verify the log call
    mock_secure_logger.log_audit_event.assert_any_call(
        severity=3,
        category="Alert",
        message="CBOR decode error: premature end of stream",
        sensitive=False,
        use_senary=False
    )


# 💾 Test File Operations
def test_save_and_load_from_file(tmp_path):
    """Test saving to and loading from a CBOR file."""
    file_path = tmp_path / "test_file.cbor"
    data = {"key": "value"}

    save_to_file(data, file_path)
    loaded_data = load_from_file(file_path)

    assert loaded_data == data


# 🚨 Test File Save Failure
def test_save_to_file_failure(mock_secure_logger, tmp_path):
    """Test failure during file save."""
    with patch('builtins.open', side_effect=IOError("Failed to save file")):
        file_path = tmp_path / "test_file.cbor"
        with pytest.raises(IOError, match="Failed to save file"):
            save_to_file({"key": "value"}, file_path)


# 🚨 Test File Load Failure
def test_load_from_file_failure(mock_secure_logger, tmp_path):
    """Test failure during file load."""
    with patch('builtins.open', side_effect=IOError("Failed to load file")):
        file_path = tmp_path / "test_file.cbor"
        with pytest.raises(IOError, match="Failed to load file"):
            load_from_file(file_path)
