import pytest
import hashlib
from src.seigr_cell.utils.integrity_verifier import verify_integrity, verify_hierarchical_integrity


def test_verify_integrity_valid():
    data = b"test data"
    correct_hash = hashlib.sha256(data).hexdigest()
    assert (
        verify_integrity(data, correct_hash) is True
    ), "Expected valid integrity check to return True"


def test_verify_integrity_invalid():
    data = b"test data"
    incorrect_hash = "incorrecthash12345"
    assert (
        verify_integrity(data, incorrect_hash) is False
    ), "Expected invalid integrity check to return False"


def test_verify_integrity_empty_data():
    data = b""
    empty_hash = hashlib.sha256(data).hexdigest()
    assert (
        verify_integrity(data, empty_hash) is True
    ), "Expected empty data with correct hash to pass integrity check"


def test_verify_hierarchical_integrity_valid():
    data = b"test data"
    # Update with manually verified root_hash
    hash_tree = {
        "chunk_size": 1024,
        "root_hash": "<manually_calculated_root_hash>",
    }
    assert verify_hierarchical_integrity(data, hash_tree) is True


def test_verify_hierarchical_integrity_invalid():
    data = b"test data"
    hash_tree = {"level_1": "incorrecthash12345"}  # Corrupted hash tree
    assert (
        verify_hierarchical_integrity(data, hash_tree) is False
    ), "Expected invalid hierarchical integrity check to fail"


def test_verify_hierarchical_integrity_empty_tree():
    data = b"test data"
    hash_tree = {}
    assert (
        verify_hierarchical_integrity(data, hash_tree) is False
    ), "Expected empty hash tree to fail integrity check"


def test_verify_hierarchical_integrity_incorrect_format():
    data = b"test data"
    hash_tree = "not_a_tree"  # Incorrect format
    with pytest.raises(TypeError):
        verify_hierarchical_integrity(data, hash_tree)


def test_verify_hierarchical_integrity_invalid_tree():
    data = b"test data"
    invalid_tree = "not_a_tree"
    with pytest.raises(TypeError):
        verify_hierarchical_integrity(data, invalid_tree)


def test_verify_hierarchical_integrity_mismatch():
    data = b"test data"
    hash_tree = {
        "chunk_size": 1024,
        "root_hash": "invalid_hash",
    }
    assert verify_hierarchical_integrity(data, hash_tree) is False
