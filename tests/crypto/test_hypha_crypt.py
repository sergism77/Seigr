# tests/crypto/test_hypha_crypt.py

import pytest
from datetime import datetime
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.key_derivation import derive_key

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


def test_encryption_decryption(hypha_crypt):
    """Test that data can be encrypted and decrypted to match the original."""
    key = hypha_crypt.generate_encryption_key(PASSWORD)
    encrypted_data = hypha_crypt.encrypt_data(key)
    decrypted_data = hypha_crypt.decrypt_data(encrypted_data, key)
    assert decrypted_data == SAMPLE_DATA, "Decrypted data does not match the original"


def test_primary_hash_generation(hypha_crypt):
    """Test that the primary hash is generated correctly."""
    primary_hash = hypha_crypt.compute_primary_hash()
    assert primary_hash is not None, "Primary hash should not be None"
    assert isinstance(primary_hash, str), "Primary hash should be a string"
    assert len(primary_hash) > 0, "Primary hash should not be empty"


def test_layered_hash_tree_generation(hypha_crypt):
    """Test that a layered hash tree is generated correctly."""
    hash_tree = hypha_crypt.compute_layered_hashes()
    assert isinstance(hash_tree, dict), "Hash tree should be a dictionary"
    assert len(hash_tree) == HASH_DEPTH, f"Hash tree should have {HASH_DEPTH} layers"
    for depth in range(1, HASH_DEPTH + 1):
        layer_key = f"Layer_{depth}"
        assert layer_key in hash_tree, f"{layer_key} should be in the hash tree"
        assert isinstance(
            hash_tree[layer_key], list
        ), f"{layer_key} should be a list of hashes"
        assert len(hash_tree[layer_key]) > 0, f"{layer_key} should contain hashes"


def test_integrity_verification_success(hypha_crypt):
    """Test that integrity verification succeeds when the hash tree matches."""
    reference_tree = hypha_crypt.compute_layered_hashes()
    verification_results = hypha_crypt.verify_integrity(reference_tree)
    assert (
        verification_results["status"] == "success"
    ), "Integrity verification should succeed"
    assert not verification_results[
        "failed_layers"
    ], "No layers should fail verification"


def test_integrity_verification_failure(hypha_crypt):
    """Test that integrity verification fails when the hash tree does not match."""
    reference_tree = hypha_crypt.compute_layered_hashes()
    reference_tree["Layer_1"][0] = "tampered_hash"  # Tamper with the hash tree
    verification_results = hypha_crypt.verify_integrity(reference_tree)
    assert (
        verification_results["status"] == "failed"
    ), "Integrity verification should fail"
    assert (
        1 in verification_results["failed_layers"]
    ), "Layer 1 should fail verification"


def test_log_integrity_verification(hypha_crypt):
    """Test that an integrity verification log entry is generated correctly."""
    status = "SUCCESS"
    verifier_id = "test_verifier"
    integrity_level = "FULL"
    details = {"note": "Test verification log"}
    verification_entry = hypha_crypt.log_integrity_verification(
        status, verifier_id, integrity_level, details
    )
    assert verification_entry.verification_id == f"{SEGMENT_ID}_verification"
    assert verification_entry.verifier_id == verifier_id
    assert verification_entry.status == verification_entry.VERIFIED
    assert verification_entry.integrity_level == integrity_level
    assert verification_entry.verification_notes == details
