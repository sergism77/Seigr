import pytest
from unittest.mock import patch, MagicMock
from cryptography.fernet import InvalidToken
from src.crypto.symmetric_utils import SymmetricUtils
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity


# 🔑 **Fixture for SymmetricUtils**
@pytest.fixture
def symmetric_utils():
    """Fixture to initialize SymmetricUtils instance."""
    return SymmetricUtils()


# ===============================
# 🔒 **Encryption Tests**
# ===============================


def test_encrypt_data(symmetric_utils):
    """Test that data encryption produces a valid ciphertext."""
    plaintext = b"Sensitive data"
    encrypted_data = symmetric_utils.encrypt_data(plaintext)

    assert encrypted_data is not None
    assert isinstance(encrypted_data, bytes)
    assert encrypted_data != plaintext  # Ensure ciphertext is different from plaintext


def test_encrypt_sensitive_data(symmetric_utils):
    """Test that encrypting sensitive data triggers a proper log."""
    plaintext = b"Secret Data"

    with patch.object(secure_logger, "log_audit_event") as mock_log:
        encrypted_data = symmetric_utils.encrypt_data(plaintext, sensitive=True)

        assert encrypted_data is not None
        mock_log.assert_called_with(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Encryption",
            message="SEIGR Encryption event logged",
        )


# ===============================
# 🔓 **Decryption Tests**
# ===============================


def test_decrypt_data(symmetric_utils):
    """Test that encrypted data can be decrypted correctly."""
    plaintext = b"Confidential Message"
    encrypted_data = symmetric_utils.encrypt_data(plaintext)
    decrypted_data = symmetric_utils.decrypt_data(encrypted_data)

    assert decrypted_data == plaintext


def test_decrypt_invalid_data(symmetric_utils):
    """Test that an invalid token raises a decryption error."""
    with pytest.raises(ValueError, match="Decryption failed: Invalid token"):
        symmetric_utils.decrypt_data(b"InvalidCiphertext")


def test_decrypt_sensitive_data(symmetric_utils):
    """Test that decrypting sensitive data triggers a proper log."""
    plaintext = b"Super Secret Data"
    encrypted_data = symmetric_utils.encrypt_data(plaintext, sensitive=True)

    with patch.object(secure_logger, "log_audit_event") as mock_log:
        decrypted_data = symmetric_utils.decrypt_data(encrypted_data, sensitive=True)

        assert decrypted_data == plaintext
        mock_log.assert_called_with(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Decryption",
            message="SEIGR Decryption event logged",
        )


# ===============================
# 🛑 **Error Handling Tests**
# ===============================


def test_encrypt_data_failure(symmetric_utils):
    """Test encryption failure due to invalid input."""
    with pytest.raises(ValueError, match="Data encryption failed."):
        symmetric_utils.encrypt_data(None)


def test_decrypt_data_failure(symmetric_utils):
    """Test decryption failure due to an invalid token."""
    with pytest.raises(ValueError, match="Decryption failed: Invalid token"):
        symmetric_utils.decrypt_data(b"InvalidData")


@patch.object(secure_logger, "log_audit_event")
def test_encryption_failure_logging(mock_log):
    """
    ✅ Fix: Ensure correct logging when encryption fails.
    """
    sym_utils = SymmetricUtils()
    with pytest.raises(ValueError, match="Data encryption failed."):
        sym_utils.encrypt_data(None)  # Invalid input to trigger failure

    mock_log.assert_any_call(
        severity=AlertSeverity.ALERT_SEVERITY_FATAL,
        category="Encryption",
        message="SEIGR_encryption_fail: Data encryption failed. Encryption key must be in bytes format.",
        sensitive=True,
    )
