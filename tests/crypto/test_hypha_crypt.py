"""
Test Suite for HyphaCrypt

Validates encryption, decryption, hashing, hash tree generation, and integrity verification
in the HyphaCrypt module.
"""

import pytest
from unittest.mock import patch
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.integrity_tools import verify_integrity
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from src.seigr_protocol.compiled.hashing_pb2 import HashAlgorithm
from src.crypto.helpers import encode_to_senary, decode_from_senary
from src.crypto.symmetric_utils import SymmetricUtils
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


@patch.object(secure_logger, "log_audit_event")
def test_generate_encryption_key_with_password(mock_log):
    """
    ✅ Fix: Ensure password-derived key is exactly 32 bytes.
    """
    password = "test_secure_password"
    sym_utils = SymmetricUtils()
    derived_key = sym_utils._generate_encryption_key(password)

    assert isinstance(derived_key, bytes), "Encryption key should be of type bytes"
    assert len(derived_key) == 32, f"Derived key length should be 32 bytes, got {len(derived_key)}"



def test_generate_encryption_key_without_password(hypha_crypt):
    """Test encryption key generation without a password."""
    key = hypha_crypt.generate_encryption_key()
    assert isinstance(key, bytes), "Encryption key should be of type bytes"
    assert len(key) == 44, "Key length should match Fernet's key length"


def test_encryption_decryption():
    """Test that encrypted data can be decrypted correctly using SymmetricUtils."""
    key = SymmetricUtils()._generate_encryption_key(PASSWORD)
    sym_utils = SymmetricUtils(encryption_key=key, use_senary=True)
    
    encrypted_data = sym_utils.encrypt_data(SAMPLE_DATA)
    decrypted_data = sym_utils.decrypt_data(encrypted_data)
    
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
    primary_hash = hypha_crypt.HASH_SEIGR_SENARY(SAMPLE_DATA)
    assert isinstance(primary_hash, str), "Primary hash should be a string"
    assert len(primary_hash) > 0, "Primary hash should not be empty"


def test_primary_hash_senary_encoding(hypha_crypt):
    """Test that Senary encoding applies correctly to hashes."""
    primary_hash = hypha_crypt.HASH_SEIGR_SENARY(SAMPLE_DATA)

    # ✅ Ensure the hash is Senary-encoded
    assert isinstance(primary_hash, str), "Hash output should be a string"
    assert primary_hash.startswith("6E"), "Senary hash should have the expected prefix"


def test_invalid_hash_algorithm(hypha_crypt):
    """Test hash generation with an unsupported algorithm."""
    with pytest.raises(ValueError):
        hypha_crypt.HASH_SEIGR_SENARY(SAMPLE_DATA, algorithm="unsupported")


### 🛡️ Integrity Verification Tests ###


def test_integrity_verification_success():
    """Test integrity verification succeeds with a valid hash."""
    reference_hash = HyphaCrypt(SAMPLE_DATA, SEGMENT_ID).HASH_SEIGR_SENARY(SAMPLE_DATA)
    assert verify_integrity(SAMPLE_DATA, reference_hash), "Integrity verification should succeed"


def test_integrity_verification_failure():
    """Test integrity verification fails with a mismatched hash."""
    reference_hash = HyphaCrypt(SAMPLE_DATA, SEGMENT_ID).HASH_SEIGR_SENARY(SAMPLE_DATA)
    tampered_data = b"Tampered Data"
    assert not verify_integrity(tampered_data, reference_hash), "Integrity check should fail"


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
