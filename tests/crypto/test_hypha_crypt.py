"""
Test Suite for HyphaCrypt

Validates encryption, decryption, hashing, hash tree generation, and integrity verification
in the HyphaCrypt module.
"""

import pytest
from datetime import datetime
from src.crypto.hypha_crypt import HyphaCrypt
import logging

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


### Encryption and Decryption Tests ###


def test_generate_encryption_key_with_password(hypha_crypt):
    """Test encryption key generation with a password."""
    key = hypha_crypt.generate_encryption_key(PASSWORD)
    assert isinstance(key, bytes), "Encryption key should be of type bytes"
    assert len(key) == 32, "Key length should match the expected derived key length"


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


### Hash and Hash Tree Tests ###


def test_primary_hash_generation(hypha_crypt):
    """Test primary hash generation."""
    primary_hash = hypha_crypt.compute_primary_hash()
    assert isinstance(primary_hash, str), "Primary hash should be a string"
    assert len(primary_hash) > 0, "Primary hash should not be empty"


def test_layered_hash_tree_generation(hypha_crypt):
    """Test hierarchical hash tree generation."""
    hypha_crypt.compute_primary_hash()
    hash_tree = hypha_crypt.compute_layered_hashes()
    assert isinstance(hash_tree, dict), "Hash tree should be a dictionary"
    assert len(hash_tree) == HASH_DEPTH, f"Hash tree should have {HASH_DEPTH} layers"

    for depth in range(1, HASH_DEPTH + 1):
        layer_key = f"Layer_{depth}"
        assert layer_key in hash_tree, f"{layer_key} should exist in the hash tree"
        assert isinstance(hash_tree[layer_key], list), f"{layer_key} should be a list"
        assert len(hash_tree[layer_key]) > 0, f"{layer_key} should contain hashes"


### Integrity Verification Tests ###


def test_integrity_verification_success(hypha_crypt):
    """Test integrity verification succeeds with a valid hash tree."""
    hypha_crypt.compute_primary_hash()
    reference_tree = hypha_crypt.compute_layered_hashes()
    verification_results = hypha_crypt.verify_integrity(reference_tree)
    assert verification_results["status"] == "success", "Integrity verification should succeed"
    assert not verification_results["failed_layers"], "No layers should fail verification"


def test_integrity_verification_failure(hypha_crypt):
    """Test integrity verification fails when the hash tree is tampered with."""
    hypha_crypt.compute_primary_hash()
    reference_tree = hypha_crypt.compute_layered_hashes()
    reference_tree["Layer_1"][0] = "tampered_hash"  # Tamper with the first hash
    verification_results = hypha_crypt.verify_integrity(reference_tree)
    assert verification_results["status"] == "failed", "Integrity verification should fail"
    assert 1 in verification_results["failed_layers"], "Layer 1 should fail verification"


### Error Handling Tests ###


def test_encrypt_data_with_invalid_key(hypha_crypt):
    """Test encrypting data with an invalid key."""
    with pytest.raises(ValueError):
        hypha_crypt.encrypt_data(key=None)


def test_decrypt_data_with_invalid_key(hypha_crypt):
    """Test decrypting data with an invalid key."""
    key = hypha_crypt.generate_encryption_key(PASSWORD)
    encrypted_data = hypha_crypt.encrypt_data(key)
    with pytest.raises(ValueError):
        hypha_crypt.decrypt_data(encrypted_data, key=None)


def test_verify_integrity_with_invalid_reference_tree(hypha_crypt):
    """Test integrity verification with an invalid reference tree."""
    with pytest.raises(Exception):
        hypha_crypt.verify_integrity(reference_tree=None)


### Logging Tests ###


def test_log_error_in_encryption(hypha_crypt, caplog):
    """Test that errors are logged during encryption failures."""
    with caplog.at_level(logging.ERROR):
        with pytest.raises(ValueError):
            hypha_crypt.encrypt_data(key=None)
    assert "encryption_fail" in caplog.text


def test_log_error_in_decryption(hypha_crypt, caplog):
    """Test that errors are logged during decryption failures."""
    key = hypha_crypt.generate_encryption_key(PASSWORD)
    encrypted_data = hypha_crypt.encrypt_data(key)
    with caplog.at_level(logging.ERROR):
        with pytest.raises(ValueError):
            hypha_crypt.decrypt_data(encrypted_data, key=None)
    assert "decryption_fail" in caplog.text


### Edge Case Tests ###


def test_empty_data_segment():
    """Test initializing HyphaCrypt with an empty data segment."""
    with pytest.raises(ValueError):
        HyphaCrypt(data=b"", segment_id=SEGMENT_ID)
