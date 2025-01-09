# src/seigr_cell/seigr_cell_metadata.py

import uuid
from datetime import datetime, timezone
from typing import Dict

from src.seigr_cell.utils.encoding_utils import deserialize_metadata
from src.seigr_cell.utils.validation_utils import validate_metadata_schema
from src.logger.secure_logger import secure_logger


class SeigrCellMetadata:
    """
    SeigrCellMetadata manages the creation, extraction, validation, and updating of metadata within Seigr Cells.
    """

    def __init__(self):
        """
        Initializes the SeigrCellMetadata manager.
        """
        secure_logger.log_audit_event(
            severity=1,
            category="Initialization",
            message="Initialized SeigrCellMetadata manager.",
            sensitive=False,
        )

    def generate_default_metadata(self, segment_id: str, access_policy: Dict = None) -> Dict:
        """
        Generates a default set of metadata, including creation timestamp and unique identifiers.

        Args:
            segment_id (str): Identifier for the Seigr Cell segment.
            access_policy (dict): Optional dictionary defining access policies.

        Returns:
            dict: Default metadata for a new Seigr Cell.
        """
        access_policy = access_policy or {"level": "public", "tags": ["initial", "seigr-cell"]}
        timestamp = datetime.now(timezone.utc).isoformat()
        cell_id = str(uuid.uuid4())
        default_metadata = {
            "cell_id": cell_id,
            "contributor_id": segment_id,
            "timestamp": timestamp,
            "version": "1.0",
            "data_hash": "",
            "lineage_hash": "",
            "access_level": access_policy.get("level", "public"),
            "tags": access_policy.get("tags", ["initial", "seigr-cell"]),
        }
        secure_logger.log_audit_event(
            severity=1,
            category="Metadata",
            message=f"Generated default metadata: {default_metadata}",
            sensitive=False,
        )
        return default_metadata

    def extract_metadata(self, encoded_cell: bytes) -> Dict:
        """
        Extracts metadata from an encoded Seigr Cell.

        Args:
            encoded_cell (bytes): The encoded Seigr Cell from which metadata will be extracted.

        Returns:
            dict: Extracted metadata from the Seigr Cell.
        """
        try:
            metadata = deserialize_metadata(encoded_cell)
            validate_metadata_schema(metadata)  # Validate the extracted metadata
            secure_logger.log_audit_event(
                severity=1,
                category="Metadata",
                message="Extracted metadata from Seigr Cell.",
                sensitive=False,
            )
            return metadata
        except Exception as e:
            secure_logger.log_audit_event(
                severity=4,
                category="Metadata",
                message=f"Failed to extract metadata: {e}",
                sensitive=True,
            )
            raise ValueError("Error extracting metadata from Seigr Cell") from e

    def update_metadata(self, current_metadata: Dict, updates: Dict) -> Dict:
        """
        Updates the metadata of a Seigr Cell with specified updates.

        Args:
            current_metadata (dict): Current metadata dictionary from the Seigr Cell.
            updates (dict): Dictionary containing updates to apply to the metadata.

        Returns:
            dict: Updated metadata dictionary.
        """
        try:
            updated_metadata = current_metadata.copy()
            updated_metadata.update(updates)

            # Update lineage and version automatically
            updated_metadata["timestamp"] = datetime.now(timezone.utc).isoformat()
            updated_metadata["version"] = self._increment_version(
                current_metadata.get("version", "1.0")
            )

            if "lineage_hash" in updates:
                updated_metadata["lineage_hash"] = updates["lineage_hash"]

            validate_metadata_schema(updated_metadata)  # Validate the updated metadata
            secure_logger.log_audit_event(
                severity=1,
                category="Metadata Update",
                message=f"Updated metadata: {updated_metadata}",
                sensitive=False,
            )
            return updated_metadata
        except Exception as e:
            secure_logger.log_audit_event(
                severity=3,
                category="Metadata Update",
                message=f"Failed to update metadata: {e}",
                sensitive=True,
            )
            raise ValueError("Error updating metadata in Seigr Cell") from e

    def _increment_version(self, current_version: str) -> str:
        """
        Increments the version of the metadata in a semantic manner.

        Args:
            current_version (str): Current version string (e.g., "1.0").

        Returns:
            str: New version string with incremented minor version.
        """
        try:
            major, minor = map(int, current_version.split("."))
            new_version = f"{major}.{minor + 1}"
            secure_logger.log_audit_event(
                severity=1,
                category="Metadata Version",
                message=f"Incremented version from {current_version} to {new_version}",
                sensitive=False,
            )
            return new_version
        except ValueError:
            secure_logger.log_audit_event(
                severity=2,
                category="Metadata Version",
                message="Invalid version format; resetting to 1.0",
                sensitive=False,
            )
            return "1.0"
