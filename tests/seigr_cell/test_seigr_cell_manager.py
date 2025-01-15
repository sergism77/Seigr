# tests/seigr_cell/test_seigr_cell_manager.py

import pytest

from src.seigr_cell.seigr_cell_manager import SeigrCellManager


@pytest.fixture
def seigr_cell_manager():
    """Fixture to initialize the SeigrCellManager for tests."""
    return SeigrCellManager()


def test_create_seigr_cell(seigr_cell_manager):
    """Test creation of a Seigr Cell with default metadata."""
    data = b"Test data for Seigr Cell"
    cell = seigr_cell_manager.create_seigr_cell(data)

    # Assert cell creation produces a non-empty output
    assert cell is not None, "Seigr Cell should not be None after creation"
    assert isinstance(cell, bytes), "Seigr Cell should be in encoded (bytes) format"


def test_encode_seigr_cell(seigr_cell_manager):
    """Test encoding data and metadata into a Seigr Cell."""
    data = b"Sample data"
    metadata = {"type": "test", "author": "seigr_user"}
    encoded_cell = seigr_cell_manager.encode_seigr_cell(data, metadata)

    assert encoded_cell is not None, "Encoded Seigr Cell should not be None"
    assert isinstance(encoded_cell, bytes), "Encoded Seigr Cell should be in bytes format"


def test_decode_seigr_cell(seigr_cell_manager):
    """Test decoding a Seigr Cell into data and metadata."""
    data = b"Sample data to decode"
    metadata = {"type": "test_decode", "author": "seigr_user"}
    encoded_cell = seigr_cell_manager.encode_seigr_cell(data, metadata)

    decoded_data, decoded_metadata = seigr_cell_manager.decode_seigr_cell(encoded_cell)

    assert decoded_data == data, "Decoded data should match the original data"
    assert decoded_metadata == metadata, "Decoded metadata should match the original metadata"


def test_validate_seigr_cell(seigr_cell_manager):
    """Test validation of a Seigr Cell structure."""
    data = b"Data to validate"
    metadata = {"type": "validation_test", "author": "seigr_user"}
    encoded_cell = seigr_cell_manager.encode_seigr_cell(data, metadata)

    is_valid = seigr_cell_manager.validate_seigr_cell(encoded_cell)

    assert is_valid, "Seigr Cell should be valid after creation and encoding"


def test_get_metadata(seigr_cell_manager):
    """Test retrieval of metadata from a Seigr Cell."""
    data = b"Data with metadata"
    metadata = {"type": "metadata_test", "author": "seigr_user"}
    encoded_cell = seigr_cell_manager.encode_seigr_cell(data, metadata)

    extracted_metadata = seigr_cell_manager.get_metadata(encoded_cell)

    assert extracted_metadata == metadata, "Extracted metadata should match the original metadata"


def test_update_metadata(seigr_cell_manager):
    """Test updating metadata within a Seigr Cell."""
    data = b"Data for update test"
    initial_metadata = {"type": "initial", "author": "seigr_user"}
    encoded_cell = seigr_cell_manager.encode_seigr_cell(data, initial_metadata)

    # Define updates to apply to the metadata
    updates = {"author": "updated_seigr_user", "version": "v1.1"}
    updated_cell = seigr_cell_manager.update_metadata(encoded_cell, updates)

    # Decode updated cell to verify the metadata changes
    _, updated_metadata = seigr_cell_manager.decode_seigr_cell(updated_cell)

    # Expected metadata after update
    expected_metadata = {
        "type": "initial",
        "author": "updated_seigr_user",
        "version": "v1.1",
    }

    assert updated_metadata == expected_metadata, "Updated metadata should reflect the changes made"
