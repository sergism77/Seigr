# src/seigr_cell/utils/metadata_handler.py

import hashlib
from datetime import datetime, timezone
from typing import Dict


def generate_data_hash(data: bytes) -> str:
    """
    Generates a SHA-256 hash of the data.

    Args:
        data (bytes): Data to hash.

    Returns:
        str: SHA-256 hash of the data.
    """
    return hashlib.sha256(data).hexdigest()


def generate_lineage_hash(cell_id: str, data_hash: str) -> str:
    """
    Generates a lineage hash based on cell ID and data hash.

    Args:
        cell_id (str): Unique cell identifier.
        data_hash (str): Hash of the cell data.

    Returns:
        str: Lineage hash.
    """
    return hashlib.sha256((cell_id + data_hash).encode()).hexdigest()


def create_metadata(
    cell_id: str,
    contributor_id: str,
    data_hash: str,
    lineage_hash: str,
    access_policy: Dict[str, str],
) -> Dict[str, str]:
    """
    Creates metadata for a SeigrCell.

    Args:
        cell_id (str): Unique cell identifier.
        contributor_id (str): Segment ID.
        data_hash (str): Hash of the cell data.
        lineage_hash (str): Lineage hash.
        access_policy (dict): Access policy for the cell.

    Returns:
        dict: Metadata dictionary.
    """
    return {
        "cell_id": cell_id,
        "contributor_id": contributor_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0",
        "data_hash": data_hash,
        "lineage_hash": lineage_hash,
        "access_level": access_policy.get("level", "public"),
        "tags": access_policy.get("tags", []),
    }
