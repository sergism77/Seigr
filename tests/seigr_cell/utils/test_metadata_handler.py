# tests/seigr_cell/utils/test_metadata_handler.py

import pytest
from src.seigr_cell.utils.metadata_handler import (
    generate_data_hash,
    generate_lineage_hash,
    create_metadata,
)


def test_generate_data_hash():
    data = b"test data"
    hash_value = generate_data_hash(data)
    assert isinstance(hash_value, str)
    assert len(hash_value) == 64  # SHA-256 produces a 64-character hex string


def test_generate_lineage_hash():
    cell_id = "cell123"
    data_hash = "datahash123"
    lineage_hash = generate_lineage_hash(cell_id, data_hash)
    assert isinstance(lineage_hash, str)
    assert len(lineage_hash) == 64


def test_create_metadata():
    cell_id = "123e4567-e89b-12d3-a456-426614174000"
    contributor_id = "segment123"
    data_hash = "abc123"
    lineage_hash = "def456"
    access_policy = {"level": "restricted", "tags": ["tag1", "tag2"]}

    metadata = create_metadata(
        cell_id, contributor_id, data_hash, lineage_hash, access_policy
    )

    assert metadata["cell_id"] == cell_id
    assert metadata["access_level"] == "restricted"
    assert "timestamp" in metadata
