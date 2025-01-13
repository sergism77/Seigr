import pytest
import uuid
from datetime import datetime, timezone
from src.seigr_cell.seigr_cell import SeigrCell
from src.logger.secure_logger import secure_logger


@pytest.fixture
def sample_data():
    """Fixture to provide sample data for tests."""
    return b"Sample data for SeigrCell testing."


@pytest.fixture
def sample_segment_id():
    """Fixture to provide a sample segment ID."""
    return str(uuid.uuid4())


@pytest.fixture
def sample_access_policy():
    """Fixture to provide a sample access policy."""
    return {"level": "restricted", "tags": ["test", "seigr-cell"]}


def test_initialize_seigr_cell(sample_segment_id, sample_data, sample_access_policy):
    """Test initializing a SeigrCell instance."""
    cell = SeigrCell(
        segment_id=sample_segment_id,
        data=sample_data,
        access_policy=sample_access_policy,
    )

    assert cell.segment_id == sample_segment_id
    assert cell.data == sample_data
    assert cell.access_policy == sample_access_policy
    assert isinstance(cell.cell_id, str), "Cell ID should be a valid string"
    assert cell.metadata is not None, "Metadata should be initialized"


def test_store_data(sample_segment_id, sample_data):
    """Test storing data in a SeigrCell."""
    cell = SeigrCell(segment_id=sample_segment_id, data=sample_data)
    encoded_data = cell.store_data(password="secure_password")

    assert isinstance(encoded_data, bytes), "Encoded data should be in bytes format"


def test_retrieve_data(sample_segment_id, sample_data):
    """Test retrieving data from a SeigrCell."""
    cell = SeigrCell(segment_id=sample_segment_id, data=sample_data)
    password = "secure_password"
    encoded_data = cell.store_data(password=password)

    retrieved_data = cell.retrieve_data(encoded_data, password=password)
    assert retrieved_data == sample_data, "Retrieved data should match the original"


def test_metadata_management(sample_segment_id, sample_data, sample_access_policy):
    """Test metadata generation and updates in a SeigrCell."""
    cell = SeigrCell(
        segment_id=sample_segment_id,
        data=sample_data,
        access_policy=sample_access_policy,
    )

    initial_metadata = cell.metadata
    assert initial_metadata["access_level"] == sample_access_policy["level"]

    # Update access policy
    new_policy = {"level": "public", "tags": ["updated"]}
    cell.update_access_policy(new_policy)

    updated_metadata = cell.metadata
    assert updated_metadata["access_level"] == "public"
    assert "updated" in updated_metadata["tags"], "Tags should reflect updates"


def test_integrity_verification(sample_segment_id, sample_data):
    """Test integrity verification for SeigrCell."""
    cell = SeigrCell(segment_id=sample_segment_id, data=sample_data)
    assert cell.verify_integrity(), "Integrity verification should succeed for unaltered data"


def test_invalid_retrieval(sample_segment_id, sample_data):
    """Test data retrieval with an incorrect password."""
    cell = SeigrCell(segment_id=sample_segment_id, data=sample_data)
    password = "secure_password"
    encoded_data = cell.store_data(password=password)

    with pytest.raises(ValueError, match="Decryption failed"):
        cell.retrieve_data(encoded_data, password="wrong_password")


def test_tampered_data_integrity(sample_segment_id, sample_data):
    """Test that tampered data fails integrity checks."""
    cell = SeigrCell(segment_id=sample_segment_id, data=sample_data)
    encoded_data = cell.store_data(password="secure_password")

    # Tamper with the encoded data
    tampered_data = bytearray(encoded_data)
    tampered_data[-1] ^= 0xFF  # Flip the last byte
    tampered_data = bytes(tampered_data)

    with pytest.raises(ValueError, match="Integrity verification failed"):
        cell.retrieve_data(tampered_data, password="secure_password")
