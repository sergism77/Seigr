import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, Any

from src.crypto.encoding_utils import serialize_metadata, deserialize_metadata
from src.seigr_cell.utils.validation_utils import validate_metadata_schema
from src.logger.secure_logger import secure_logger


class SeigrCellMetadata:
    """
    SeigrCellMetadata manages the creation, extraction, validation, and updating
    of metadata within Seigr Cells. It also supports hash generation for data integrity.
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

    def generate_metadata(self, data: bytes, segment_id: str, access_policy: Dict = None) -> Dict:
        """
        Generates metadata for a Seigr Cell, including hashes and default attributes.

        Args:
            data (bytes): Data for which metadata is being generated.
            segment_id (str): Segment ID associated with the Seigr Cell.
            access_policy (dict): Access control policies.

        Returns:
            dict: Generated metadata dictionary.
        """
        try:
            access_policy = access_policy or {"level": "public", "tags": []}
            data_hash = self.generate_data_hash(data)
            lineage_hash = self.generate_lineage_hash(segment_id, data_hash)
            metadata = {
                "cell_id": str(uuid.uuid4()),
                "contributor_id": segment_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": "1.0",
                "data_hash": data_hash,
                "lineage_hash": lineage_hash,
                "access_level": access_policy.get("level", "public"),
                "tags": access_policy.get("tags", []),
            }
            validate_metadata_schema(metadata)
            secure_logger.log_audit_event(
                severity=1,
                category="Metadata",
                message=f"Generated metadata: {metadata}",
                sensitive=False,
            )
            return metadata
        except Exception as e:
            secure_logger.log_audit_event(
                severity=3,
                category="Metadata",
                message=f"Failed to generate metadata: {e}",
                sensitive=True,
            )
            raise ValueError("Error generating metadata") from e

    def generate_data_hash(self, data: bytes) -> str:
        """
        Generates a SHA-256 hash of the provided data.

        Args:
            data (bytes): Data to hash.

        Returns:
            str: Hexadecimal SHA-256 hash of the data.
        """
        return hashlib.sha256(data).hexdigest()

    def generate_lineage_hash(self, segment_id: str, data_hash: str) -> str:
        """
        Generates a lineage hash by combining segment ID and data hash.

        Args:
            segment_id (str): Segment identifier.
            data_hash (str): Data hash.

        Returns:
            str: Hexadecimal SHA-256 lineage hash.
        """
        return hashlib.sha256((segment_id + data_hash).encode()).hexdigest()

    def serialize_metadata(self, metadata: Dict[str, Any]) -> bytes:
        """
        Serializes metadata into a JSON-encoded binary format.

        Args:
            metadata (dict): Metadata dictionary.

        Returns:
            bytes: Serialized metadata.
        """
        return serialize_metadata(metadata)

    def deserialize_metadata(self, serialized_data: bytes) -> Dict[str, Any]:
        """
        Deserializes binary metadata back into a Python dictionary.

        Args:
            serialized_data (bytes): Serialized metadata.

        Returns:
            dict: Deserialized metadata dictionary.
        """
        return deserialize_metadata(serialized_data)

    def update_metadata(self, metadata: Dict, updates: Dict) -> Dict:
        """
        Updates metadata with new values and automatically updates lineage and version.

        Args:
            metadata (dict): Current metadata dictionary.
            updates (dict): Updates to apply.

        Returns:
            dict: Updated metadata.
        """
        try:
            updated_metadata = metadata.copy()
            updated_metadata.update(updates)
            updated_metadata["timestamp"] = datetime.now(timezone.utc).isoformat()
            updated_metadata["version"] = self._increment_version(metadata.get("version", "1.0"))
            if "data_hash" in updates:
                updated_metadata["lineage_hash"] = self.generate_lineage_hash(
                    updated_metadata["cell_id"], updates["data_hash"]
                )
            validate_metadata_schema(updated_metadata)
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
            raise ValueError("Error updating metadata") from e

    def _increment_version(self, current_version: str) -> str:
        """
        Increments the version of metadata in a semantic manner.

        Args:
            current_version (str): Current version string.

        Returns:
            str: Incremented version string.
        """
        try:
            major, minor = map(int, current_version.split("."))
            return f"{major}.{minor + 1}"
        except ValueError:
            return "1.0"
