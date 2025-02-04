"""
Test Suite for HyphaCrypt

Validates encryption, decryption, hashing, hash tree generation, and integrity verification
in the HyphaCrypt module.
"""

import pytest
from unittest.mock import patch
from src.crypto.hypha_crypt import HyphaCrypt
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from src.seigr_protocol.compiled.hashing_pb2 import HashAlgorithm
from src.crypto.helpers import encode_to_senary, decode_from_senary
import base64

# Sample data for tests
SAMPLE_DATA = b"This is a test data segment."
SEGMENT_ID = "test_segment"
PASSWORD = "test_password"
HASH_DEPTH = 3
USE_SENARY = True


@pytest.fixture
def hypha_crypt():
    """Fixture to initialize HyphaCrypt instance."""
    return HyphaCrypt(
        data=SAMPLE_DATA,
        segment_id=SEGMENT_ID,
        hash_depth=HASH_DEPTH,
        use_senary=USE_SENARY,
    )


### 🗝️ Encryption and Decryption Tests ###


def test_generate_encryption_key_with_password(hypha_crypt):
    """Test encryption key generation with a password."""
    key = hypha_crypt.generate_encryption_key(PASSWORD)
    assert isinstance(key, bytes), "Encryption key should be of type bytes"
    assert len(base64.urlsafe_b64decode(key)) == 32, "Derived key length should be 32 bytes"


def test_generate_encryption_key_without_password(hypha_crypt):
    """Test encryption key generation without a password."""
    key = hypha_crypt.generate_encryption_key()
    assert isinstance(key, bytes), "Encryption key should be of type bytes"
    assert len(key) == 44, "Key length should match Fernet's key length"


def test_encryption_decryption(hypha_crypt):
    """Test that encrypted data can be decrypted correctly."""
    key = hypha_crypt.generate_encryption_key(PASSWORD)
    encrypted_data = hypha_crypt.encrypt_data(key)
    decrypted_data = hypha_crypt.decrypt_data(encrypted_data, key)
    assert decrypted_data == SAMPLE_DATA, "Decrypted data does not match the original"


def test_senary_encryption_decryption(hypha_crypt):
    """Test encryption & decryption with Senary encoding enabled."""
    key = hypha_crypt.generate_encryption_key(PASSWORD)
    encrypted_data = hypha_crypt.encrypt_data(key)

    # Ensure encryption result is Senary-encoded
    assert isinstance(encrypted_data, str), "Encrypted output should be a string"
    assert encrypted_data.startswith("6E"), "Encrypted Senary encoding should have proper prefix"

    decrypted_data = hypha_crypt.decrypt_data(encrypted_data, key)
    assert decrypted_data == SAMPLE_DATA, "Decryption failed for Senary-encoded data"


@patch.object(secure_logger, "log_audit_event")
def test_encryption_retry_logic(mock_log, hypha_crypt):
    """Test retry logic for encryption failures."""
    with patch("cryptography.fernet.Fernet.encrypt", side_effect=Exception("Transient Error")):
        with pytest.raises(Exception):
            hypha_crypt.encrypt_data(key=hypha_crypt.generate_encryption_key(PASSWORD))

    assert mock_log.call_count >= 2  # Ensure retry attempts are logged
    mock_log.assert_any_call(
        severity=AlertSeverity.ALERT_SEVERITY_FATAL,
        category="Encryption",
        message="SEIGR_encryption_fail: Data encryption failed. Transient Error",
        sensitive=True,
    )


@patch.object(secure_logger, "log_audit_event")
def test_decryption_retry_logic(mock_log, hypha_crypt):
    """Test retry logic for decryption failures."""
    key = hypha_crypt.generate_encryption_key(PASSWORD)
    encrypted_data = hypha_crypt.encrypt_data(key)
    with patch("cryptography.fernet.Fernet.decrypt", side_effect=Exception("Transient Error")):
        with pytest.raises(Exception):
            hypha_crypt.decrypt_data(encrypted_data, key)

    assert mock_log.call_count >= 2  # Ensure retry attempts are logged
    mock_log.assert_any_call(
        severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
        category="Decryption",
        message="SEIGR_decryption_fail: Data decryption failed. Transient Error",
        sensitive=True,
    )


### 🔗 Hashing Tests ###


def test_primary_hash_generation(hypha_crypt):
    """Test primary hash generation."""
    primary_hash = hypha_crypt.hypha_hash(SAMPLE_DATA)
    assert isinstance(primary_hash, str), "Primary hash should be a string"
    assert len(primary_hash) > 0, "Primary hash should not be empty"


def test_primary_hash_senary_encoding(hypha_crypt):
    """Test that Senary encoding applies correctly to hashes."""
    primary_hash = hypha_crypt.hypha_hash(SAMPLE_DATA)

    # ✅ Ensure the hash is Senary-encoded
    assert isinstance(primary_hash, str), "Hash output should be a string"
    assert primary_hash.startswith("6E"), "Senary hash should have the expected prefix"


def test_invalid_hash_algorithm(hypha_crypt):
    """Test hash generation with an unsupported algorithm."""
    with pytest.raises(ValueError):
        hypha_crypt.hypha_hash(SAMPLE_DATA, algorithm="unsupported")


### 🛡️ Integrity Verification Tests ###


def test_integrity_verification_success(hypha_crypt):
    """Test integrity verification succeeds with a valid hash tree."""
    reference_tree = {f"Layer_{i}": ["hash_value"] for i in range(1, HASH_DEPTH + 1)}
    verification_results = hypha_crypt.verify_integrity(reference_tree)
    assert verification_results["status"] == "success", "Integrity verification should succeed"


def test_integrity_verification_failure(hypha_crypt):
    """Test integrity verification fails with an altered hash tree."""
    reference_tree = {f"Layer_{i}": ["hash_value"] for i in range(1, HASH_DEPTH + 1)}
    reference_tree["Layer_1"][0] = "tampered_hash"
    verification_results = hypha_crypt.verify_integrity(reference_tree)
    assert verification_results["status"] == "failed", "Integrity verification should fail"
    assert "error" in verification_results, "Error message should be included in failed result"


### 🛡️ Error Handling Tests ###


@patch.object(secure_logger, "log_audit_event")
def test_encrypt_data_with_invalid_key(mock_log, hypha_crypt):
    """Test encrypting data with an invalid key."""
    with pytest.raises(Exception):
        hypha_crypt.encrypt_data(key=None)

    mock_log.assert_any_call(
        severity=AlertSeverity.ALERT_SEVERITY_FATAL,
        category="Encryption",
        message="SEIGR_encryption_fail: Data encryption failed. SEIGR Encryption key must be provided.",
        sensitive=True,
    )


@patch.object(secure_logger, "log_audit_event")
def test_decrypt_data_with_invalid_key(mock_log, hypha_crypt):
    """Test decrypting data with an invalid key."""
    with pytest.raises(Exception):
        hypha_crypt.decrypt_data(b"invalid_data", key=None)

    mock_log.assert_any_call(
        severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
        category="Decryption",
        message="SEIGR_decryption_fail: Data decryption failed. SEIGR Decryption key must be provided.",
        sensitive=True,
    )
