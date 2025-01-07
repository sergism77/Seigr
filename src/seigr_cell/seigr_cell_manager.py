# src/seigr_cell/seigr_cell_metadata.py

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, Any

from src.utils.validation_utils import validate_metadata_schema
from src.seigr_cell.utils.encoding_utils import serialize_metadata, deserialize_metadata


class SeigrCellMetadata:
    """
    Handles the generation, validation, extraction, and updating of metadata for Seigr Cells.
    """

    def __init__(self, segment_id: str):
        """
        Initializes the SeigrCellMetadata manager.

        Args:
            segment_id (str): Identifier for the Seigr Cell segment.
        """
        self.segment_id = segment_id

    def generate_default_metadata(self, access_policy: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generates default metadata for a Seigr Cell.

        Args:
            access_policy (dict): Optional access policy for the Seigr Cell.

        Returns:
            dict: A dictionary containing default metadata.
        """
        access_policy = access_policy or {"level": "public", "tags": ["initial", "seigr-cell"]}
        timestamp = datetime.now(timezone.utc).isoformat()
        cell_id = str(uuid.uuid4())
        data_hash = hashlib.sha256(b"").hexdigest()
        lineage_hash = hashlib.sha256((cell_id + data_hash).encode()).hexdigest()

        metadata = {
            "cell_id": cell_id,
            "contributor_id": self.segment_id,
            "timestamp": timestamp,
            "version": "1.0",
            "data_hash": data_hash,
            "lineage_hash": lineage_hash,
            "access_level": access_policy.get("level", "public"),
            "tags": access_policy.get("tags", ["initial", "seigr-cell"]),
        }

        return metadata

    def validate_metadata(self, metadata: Dict[str, Any]) -> bool:
        """
        Validates the structure and content of metadata.

        Args:
            metadata (dict): Metadata dictionary to validate.

        Returns:
            bool: True if metadata is valid, False otherwise.
        """
        return validate_metadata_schema(metadata)

    def extract_metadata(self, encoded_cell: bytes) -> Dict[str, Any]:
        """
        Extracts metadata from an encoded Seigr Cell.

        Args:
            encoded_cell (bytes): Encoded Seigr Cell data.

        Returns:
            dict: Extracted metadata dictionary.
        """
        try:
            metadata = deserialize_metadata(encoded_cell)
            if self.validate_metadata(metadata):
                return metadata
            else:
                raise ValueError("Extracted metadata failed validation.")
        except Exception as e:
            raise ValueError(f"Failed to extract metadata: {e}")

    def update_metadata(self, metadata: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
        """
        Updates metadata with new values while preserving lineage.

        Args:
            metadata (dict): Original metadata.
            updates (dict): Dictionary with metadata updates.

        Returns:
            dict: Updated metadata dictionary.
        """
        metadata["version"] = str(float(metadata.get("version", "1.0")) + 0.1)
        metadata["timestamp"] = datetime.now(timezone.utc).isoformat()

        if "access_level" in updates:
            metadata["access_level"] = updates["access_level"]

        if "tags" in updates:
            metadata["tags"].extend(updates["tags"])

        if "lineage_hash" in updates:
            metadata["lineage_hash"] = hashlib.sha256(
                (metadata["cell_id"] + metadata["data_hash"]).encode()
            ).hexdigest()

        if not self.validate_metadata(metadata):
            raise ValueError("Updated metadata failed validation.")

        return metadata
