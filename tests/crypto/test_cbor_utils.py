import pytest
from unittest.mock import patch, MagicMock, call
from src.crypto.cbor_utils import encode_data, decode_data
from src.seigr_protocol.compiled.encryption_pb2 import EncryptedData
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity


@pytest.fixture
def mock_secure_logger():
    with patch.object(secure_logger, "log_audit_event") as mock_logger:
        yield mock_logger


# 📝 Test: Encoding Success
def test_encode_data(mock_secure_logger):
    """Test successful CBOR encoding."""
    data = {"key": "value"}
    result = encode_data(data)
    assert isinstance(result, EncryptedData)
    assert result.ciphertext is not None

    # Verify the log call
    mock_secure_logger.assert_any_call(
        severity=AlertSeverity.ALERT_SEVERITY_INFO,
        category="CBOR Encoding",
        message="✅ Data successfully encoded to CBOR format.",
        sensitive=False,
        use_senary=False,
    )


# 🛠️ Test: Encoding Failure
def test_encode_data_failure(mock_secure_logger):
    """Test CBOR encoding failure."""
    with patch("cbor2.dumps", side_effect=Exception("Mocked failure")):
        with pytest.raises(ValueError, match="CBOR encoding error occurred"):
            encode_data({"key": "value"})

    # Validate log call allowing extra fields without failing on missing `sensitive`
    assert any(
        call_kwargs["severity"] == AlertSeverity.ALERT_SEVERITY_CRITICAL
        and call_kwargs["category"] == "CBOR Operations"
        and call_kwargs["message"] == "❌ CBOR encoding error: Mocked failure"
        and call_kwargs.get("sensitive", False) is False
        and call_kwargs.get("use_senary", False) is False
        for call_kwargs in (call.kwargs for call in mock_secure_logger.call_args_list)
    )


# 🔄 Test: Decoding Success
def test_decode_data(mock_secure_logger):
    """Test successful CBOR decoding."""
    data = {"key": "value"}
    encrypted = encode_data(data)
    decoded = decode_data(encrypted)
    assert decoded == {"key": "value"}

    # Verify log calls
    expected_calls = [
        call(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="CBOR Encoding",
            message="✅ Data successfully encoded to CBOR format.",
            sensitive=False,
            use_senary=False,
        ),
        call(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="CBOR Decoding",
            message="✅ Data successfully decoded from CBOR format.",
            sensitive=False,
            use_senary=False,
        ),
    ]

    mock_secure_logger.assert_has_calls(expected_calls, any_order=True)


# 🚨 Test: Decoding Invalid Data
def test_decode_invalid_cbor_data(mock_secure_logger):
    """Test decoding malformed CBOR data raises ValueError."""
    invalid_data = EncryptedData(ciphertext=b"\x9f\x9f\x00")
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(invalid_data)

    # Validate log call allowing extra fields without failing on missing `sensitive`
    assert any(
        call_kwargs["severity"] == AlertSeverity.ALERT_SEVERITY_CRITICAL
        and call_kwargs["category"] == "CBOR Operations"
        and "❌ CBOR decode error" in call_kwargs["message"]
        and call_kwargs.get("sensitive", False) is False
        and call_kwargs.get("use_senary", False) is False
        for call_kwargs in (call.kwargs for call in mock_secure_logger.call_args_list)
    )


# 🛡️ Test: Secure Logging on Error
def test_secure_logging_on_error(mock_secure_logger):
    """Test secure logging during decode error scenarios."""
    invalid_data = EncryptedData(ciphertext=b"\x9f\x9f\x00")
    with pytest.raises(ValueError, match="CBOR decode error"):
        decode_data(invalid_data)

    # Validate log call allowing extra fields without failing on missing `sensitive`
    assert any(
        call_kwargs["severity"] == AlertSeverity.ALERT_SEVERITY_CRITICAL
        and call_kwargs["category"] == "CBOR Operations"
        and "❌ CBOR decode error" in call_kwargs["message"]
        and call_kwargs.get("sensitive", False) is False
        and call_kwargs.get("use_senary", False) is False
        for call_kwargs in (call.kwargs for call in mock_secure_logger.call_args_list)
    )
