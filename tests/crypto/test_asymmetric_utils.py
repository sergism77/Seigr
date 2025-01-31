import pytest
from unittest.mock import patch, MagicMock
from src.crypto.asymmetric_utils import (
    generate_key_pair,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
    sign_data,
    verify_signature,
)
from src.crypto.alert_utils import trigger_alert  # ✅ Use correct alerting
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity, AlertType
from cryptography.hazmat.primitives import serialization

# Constants for tests
INVALID_KEY = b"Invalid key data"
TEST_DATA = b"Sample data for signing"


# Fixture
@pytest.fixture
def key_pair():
    """Fixture to generate an asymmetric key pair."""
    return generate_key_pair()


# --- Alert Trigger Test ---
@patch("src.logger.secure_logger.secure_logger.log_audit_event")
def test_trigger_alert(mock_log_audit_event):
    """Test triggering an alert logs the correct warning message."""
    trigger_alert(
        message="Test alert message",
        severity=AlertSeverity.ALERT_SEVERITY_WARNING,
        alert_type=AlertType.ALERT_TYPE_SECURITY,
        source_component="asymmetric_utils",
    )

    # ✅ Assert call while ignoring timestamp and log_data
    mock_log_audit_event.assert_called_once()
    actual_call = mock_log_audit_event.call_args.kwargs

    assert actual_call["severity"] == AlertSeverity.ALERT_SEVERITY_WARNING
    assert actual_call["category"] == "Cryptography"
    assert actual_call["message"] == "Test alert message"
    assert actual_call.get("sensitive", False) is False  # ✅ FIXED: Avoid KeyError
    assert actual_call.get("use_senary", False) is False  # ✅ Ensure `use_senary` is present


# 🔑 Test: Key Generation Failure Retries
@patch("src.crypto.asymmetric_utils.generate_rsa_key_pair", side_effect=Exception("Key generation failed"))
@patch("time.sleep", return_value=None)
@patch("src.logger.secure_logger.secure_logger.log_audit_event")
def test_generate_key_pair_retry(mock_log_audit_event, mock_sleep, mock_generate_rsa_key_pair):
    """Test that key generation retries upon failure and raises ValueError after retries."""
    retry_attempts = 3
    retry_delay = 1

    with pytest.raises(ValueError, match="Failed to generate RSA key pair after retries."):
        generate_key_pair(retry_attempts=retry_attempts, retry_delay=retry_delay)

    assert mock_generate_rsa_key_pair.call_count == retry_attempts
    assert mock_sleep.call_count == retry_attempts - 1

    # ✅ FIX: Correct category to "Key Management"
    assert any(
        call_kwargs["severity"] == AlertSeverity.ALERT_SEVERITY_CRITICAL
        and call_kwargs["category"] == "Key Management"
        and call_kwargs["message"] == "Failed to generate RSA key pair after retries."
        and call_kwargs.get("sensitive", False) is False
        and call_kwargs.get("use_senary", False) is False
        for call_kwargs in (call.kwargs for call in mock_log_audit_event.call_args_list)
    )


# 🔑 Test: Private Key Load Failure
@patch("time.sleep", return_value=None)
@patch("cryptography.hazmat.primitives.serialization.load_pem_private_key", side_effect=Exception("Private key load failed"))
@patch("src.logger.secure_logger.secure_logger.log_audit_event")
def test_load_private_key_retry(mock_log_audit_event, mock_load_private_key, mock_sleep):
    """Test private key loading retries upon failure."""
    with pytest.raises(ValueError, match="Failed to load RSA private key."):
        load_private_key(b"invalid_key", retry_attempts=2)

    assert mock_sleep.call_count == 1

    # ✅ FIX: Correct logging category
    assert any(
        call_kwargs["severity"] == AlertSeverity.ALERT_SEVERITY_WARNING
        and call_kwargs["category"] == "Key Management"
        and "Private key load failed" in call_kwargs["message"]
        and call_kwargs.get("sensitive", False) is False
        and call_kwargs.get("use_senary", False) is False
        for call_kwargs in (call.kwargs for call in mock_log_audit_event.call_args_list)
    )


# --- Signing and Verification Tests ---
def test_sign_and_verify_signature(key_pair):
    """Test valid data signing and signature verification."""
    signature = sign_data(TEST_DATA, key_pair.private_key)
    assert isinstance(signature, bytes)

    is_valid = verify_signature(TEST_DATA, signature, key_pair.public_key)
    assert is_valid


def test_verify_signature_with_tampered_data(key_pair):
    """Test verification fails with tampered data."""
    signature = sign_data(TEST_DATA, key_pair.private_key)
    assert not verify_signature(b"Tampered data", signature, key_pair.public_key)


# --- Serialization and Loading Tests ---
def test_serialize_and_load_public_key(key_pair):
    """Test public key serialization and reloading."""
    serialized_key = serialize_public_key(key_pair.public_key)
    reloaded_key = load_public_key(serialized_key)
    assert reloaded_key.public_numbers() == key_pair.public_key.public_numbers()


def test_serialize_and_load_private_key(key_pair):
    """Test private key serialization and reloading."""
    serialized_key = serialize_private_key(key_pair.private_key)
    reloaded_key = load_private_key(serialized_key)
    assert reloaded_key.private_numbers() == key_pair.private_key.private_numbers()


# --- Invalid Key Tests ---
def test_load_invalid_public_key():
    """Ensure an invalid public key raises ValueError."""
    with pytest.raises(ValueError, match="Failed to load RSA public key"):
        load_public_key(b"invalid_key")


def test_load_invalid_private_key():
    """Ensure an invalid private key raises ValueError."""
    with pytest.raises(ValueError, match="Failed to load RSA private key"):
        load_private_key(b"invalid_key")


# --- Empty Data Handling ---
def test_sign_data_with_empty_data(key_pair):
    """Ensure signing empty data raises ValueError."""
    with pytest.raises(ValueError, match="Cannot sign empty data"):
        sign_data(b"", key_pair.private_key)


def test_verify_signature_with_empty_data(key_pair):
    """Ensure signature verification fails with empty data."""
    signature = sign_data(TEST_DATA, key_pair.private_key)
    assert not verify_signature(b"", signature, key_pair.public_key)
