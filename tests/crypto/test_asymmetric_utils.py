import pytest
from unittest.mock import patch
from src.crypto.asymmetric_utils import (
    generate_key_pair,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
    sign_data,
    verify_signature,
    _trigger_alert,
)
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
    ErrorSeverity,
)
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity


# Constants for tests
TEST_DATA = b"Sample data for signing"
INVALID_KEY = b"Invalid key data"
INVALID_SIGNATURE = b"InvalidSignature"


@pytest.fixture
def key_pair():
    """Fixture to generate an asymmetric key pair."""
    return generate_key_pair()


# --- Key Generation Tests ---
def test_generate_key_pair():
    """Test key pair generation produces valid, non-empty keys."""
    key_pair = generate_key_pair()
    assert isinstance(key_pair.public_key, bytes), "Public key should be in bytes."
    assert isinstance(key_pair.private_key, bytes), "Private key should be in bytes."
    assert len(key_pair.public_key) > 0, "Public key should not be empty."
    assert len(key_pair.private_key) > 0, "Private key should not be empty."


# --- Alert Trigger Test ---
@patch("src.crypto.asymmetric_utils.logger.warning")
def test_trigger_alert(mock_logger):
    """Test triggering an alert logs the correct warning message."""
    _trigger_alert("Test alert message", AlertSeverity.ALERT_SEVERITY_WARNING)
    mock_logger.assert_called_once()
    assert "Alert triggered" in mock_logger.call_args[0][0], "Alert log message mismatch"


# --- Retry Mechanism Tests ---
from unittest.mock import patch
import pytest
from src.crypto.asymmetric_utils import generate_key_pair

@patch("time.sleep", return_value=None)
@patch("src.crypto.asymmetric_utils.generate_rsa_key_pair", side_effect=Exception("Key generation failed"))
def test_generate_key_pair_retry(mock_generate_rsa_key_pair, mock_sleep):
    """Test that key generation retries upon failure and raises ValueError after retries."""
    print("DEBUG: Starting test_generate_key_pair_retry.")  # Debug Print
    
    with pytest.raises(ValueError, match="Failed to generate RSA key pair after retries"):
        generate_key_pair(retry_attempts=3, retry_delay=1)
    
    print(f"DEBUG: time.sleep called {mock_sleep.call_count} times.")  # Debug Print
    print(f"DEBUG: generate_rsa_key_pair called {mock_generate_rsa_key_pair.call_count} times.")  # Debug Print

    assert mock_sleep.call_count == 2, f"Expected 2 retries, but got {mock_sleep.call_count}"
    assert mock_generate_rsa_key_pair.call_count == 3, f"Expected 3 attempts, but got {mock_generate_rsa_key_pair.call_count}"


@patch("time.sleep", return_value=None)
def test_load_private_key_retry(mock_sleep):
    """Test that private key loading retries upon failure."""
    with patch(
        "cryptography.hazmat.primitives.serialization.load_pem_private_key",
        side_effect=Exception("Private key load failed"),
    ):
        with pytest.raises(ValueError, match="Failed to load RSA private key"):
            load_private_key(INVALID_KEY, retry_attempts=2)
    assert mock_sleep.call_count == 2, f"Expected 2 retries, got {mock_sleep.call_count}"


# --- Signing and Verification Tests ---
def test_sign_and_verify_signature(key_pair):
    """Test valid data signing and signature verification."""
    signature = sign_data(TEST_DATA, key_pair.private_key)
    assert isinstance(signature, bytes), "Signature should be in bytes."
    assert len(signature) > 0, "Signature should not be empty."

    is_valid = verify_signature(TEST_DATA, signature, key_pair.public_key)
    assert is_valid, "Signature verification should pass with correct data and keys."


def test_verify_signature_with_tampered_data(key_pair):
    """Test signature verification fails with tampered data."""
    signature = sign_data(TEST_DATA, key_pair.private_key)
    tampered_data = b"Tampered data"
    is_valid = verify_signature(tampered_data, signature, key_pair.public_key)
    assert not is_valid, "Verification should fail with tampered data."


def test_verify_signature_with_invalid_key(key_pair):
    """Test signature verification fails with an invalid key."""
    signature = sign_data(TEST_DATA, key_pair.private_key)
    alt_key_pair = generate_key_pair()
    is_valid = verify_signature(TEST_DATA, signature, alt_key_pair.public_key)
    assert not is_valid, "Verification should fail with an invalid key."


# --- Serialization and Deserialization Tests ---
def test_serialize_and_load_public_key():
    """Test that a public key can be serialized and reloaded accurately."""
    key_pair = generate_key_pair()
    public_key = load_public_key(key_pair.public_key)

    serialized_public_key = serialize_public_key(public_key)
    reloaded_public_key = load_public_key(serialized_public_key)

    assert serialized_public_key == key_pair.public_key, "Serialized public key should match the original."
    assert reloaded_public_key.public_numbers() == public_key.public_numbers(), "Reloaded public key should match."


def test_serialize_and_load_private_key(key_pair):
    """Test private key serialization and deserialization."""
    private_key = load_private_key(key_pair.private_key)
    serialized_private_key = serialize_private_key(private_key)
    reloaded_private_key = load_private_key(serialized_private_key)

    assert serialized_private_key == key_pair.private_key, "Serialized private key mismatch."
    assert reloaded_private_key.private_numbers() == private_key.private_numbers(), "Reloaded private key mismatch."


# --- Invalid Key Tests ---
def test_load_invalid_public_key():
    """Test loading an invalid public key raises a ValueError."""
    with pytest.raises(ValueError, match="Failed to load RSA public key"):
        load_public_key(INVALID_KEY)


def test_load_invalid_private_key():
    """Test loading an invalid private key raises a ValueError."""
    with pytest.raises(ValueError, match="Failed to load RSA private key"):
        load_private_key(INVALID_KEY)


# --- Edge Case Tests ---
def test_sign_data_with_empty_data(key_pair):
    """Test signing empty data raises ValueError."""
    with pytest.raises(ValueError):
        sign_data(b"", key_pair.private_key)


def test_verify_signature_with_empty_data(key_pair):
    """Test verifying an empty data signature."""
    signature = sign_data(TEST_DATA, key_pair.private_key)
    is_valid = verify_signature(b"", signature, key_pair.public_key)
    assert not is_valid, "Verification should fail with empty data."
