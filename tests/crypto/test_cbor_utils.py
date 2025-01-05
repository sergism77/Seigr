import pytest
from unittest.mock import patch, MagicMock
from src.crypto.cbor_utils import encode_data, decode_data
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity


@pytest.fixture
def mock_secure_logger():
    with patch.object(secure_logger, 'log_audit_event') as mock_logger:
        yield mock_logger


# 📝 Test: Encoding Success
def test_encode_data(mock_secure_logger):
    """Test successful CBOR encoding."""
    data = {"key": "value"}
    result = encode_data(data)
    assert isinstance(result, EncryptedData)
    assert result.ciphertext is not None

    # Verify the log call
    mock_secure_logger.assert_called_with(
        severity=AlertSeverity.ALERT_SEVERITY_INFO,
        category="Encode",
        message="Data successfully encoded to CBOR format",
        sensitive=False,
        use_senary=False
    )


# 🛠️ Test: Encoding Failure
def test_encode_data_failure(mock_secure_logger):
    """Test CBOR encoding failure."""
    with patch('cbor2.dumps', side_effect=Exception("Mocked failure")):
        with pytest.raises(ValueError, match="CBOR encoding error occurred"):
            encode_data({"key": "value"})

    mock_secure_logger.assert_called_with(
        severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
        category="Alert",
        message="CBOR encoding error: Mocked failure",
        sensitive=False,
        use_senary=False
    )


# 🔄 Test: Decoding Success
def test_decode_data(mock_secure_logger):
    """Test successful CBOR decoding."""
    data = {"key": "value"}
    encrypted = encode_data(data)
    decoded = decode_data(encrypted)
    assert decoded == {"key": "value"}

    # Verify the log calls
    mock_secure_logger.assert_any_call(
        severity=AlertSeverity.ALERT_SEVERITY_INFO,
        category="Encode",
        message="Data successfully encoded to CBOR format",
        sensitive=False,
        use_senary=False
    )
    mock_secure_logger.assert_any_call(
        severity=AlertSeverity.ALERT_SEVERITY_INFO,
        category="Decode",
        message="Data successfully decoded from CBOR format",
        sensitive=False,
        use_senary=False
    )


# 🚨 Test: Decoding Invalid Data
def test_decode_invalid_cbor_data(mock_secure_logger):
    """Test decoding malformed CBOR data raises ValueError."""
    invalid_data = EncryptedData(ciphertext=b'\x9f\x9f\x00')
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(invalid_data)

    mock_secure_logger.assert_any_call(
        severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
        category="Alert",
        message="CBOR decode error: premature end of stream (expected to read 1 bytes, got 0 instead)",
        sensitive=False,
        use_senary=False
    )


# 🛡️ Test: Secure Logging on Error
def test_secure_logging_on_error(mock_secure_logger):
    """Test secure logging during decode error scenarios."""
    invalid_data = EncryptedData(ciphertext=b'\x9f\x9f\x00')
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(invalid_data)

    mock_secure_logger.assert_any_call(
        severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
        category="Alert",
        message="CBOR decode error: premature end of stream (expected to read 1 bytes, got 0 instead)",
        sensitive=False,
        use_senary=False
    )
