import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from google.protobuf.timestamp_pb2 import Timestamp
from src.crypto.hypha_crypt import HyphaCrypt
from src.logger.secure_logger import secure_logger
from src.utils.timestamp_utils import get_current_protobuf_timestamp
from src.utils.timestamp_utils import from_json_string_to_protobuf


class LineageEntry:
    """
    Represents a lineage entry capturing metadata and hash information about a specific
    lineage event, allowing for version tracking and integrity verification.
    """

    def __init__(
        self,
        version: str,
        action: str,
        creator_id: str,
        contributor_id: str,
        previous_hashes: Optional[List[str]] = None,
        metadata: Optional[Dict] = None,
    ):
        """
        Initializes a LineageEntry instance to capture and hash details of a lineage event.

        Args:
            version (str): Version identifier for the lineage entry format.
            action (str): Action description, e.g., "create", "update".
            creator_id (str): Unique identifier of the creator.
            contributor_id (str): Unique identifier of the contributor for this entry.
            previous_hashes (Optional[List[str]]): List of previous entry hashes.
            metadata (Optional[Dict]): Additional metadata related to this entry.
        """
        self.version = version
        self.action = action
        self.creator_id = creator_id
        self.contributor_id = contributor_id
        self.previous_hashes = previous_hashes or []
        self.metadata = metadata or {}

        # ✅ Use Protobuf Timestamp for standardized event tracking
        timestamp = get_current_protobuf_timestamp()

        # Validate fields
        self._validate_fields()

        # 🔐 Compute entry hash upon initialization
        self.entry_hash = self.calculate_hash()

        secure_logger.log_audit_event(
            "info",
            "LineageEntry",
            f"Initialized LineageEntry: {self.to_dict()}",
        )

    def _validate_fields(self):
        """Ensures that essential fields are properly initialized."""
        if not all([self.version, self.action, self.creator_id, self.contributor_id]):
            secure_logger.log_audit_event(
                "error",
                "LineageEntry",
                "Initialization failed due to missing required fields.",
            )
            raise ValueError("version, action, creator_id, and contributor_id are required fields.")
        secure_logger.log_audit_event("debug", "LineageEntry", "All required fields validated.")

    def calculate_hash(self) -> str:
        """
        Calculates and returns the hash of the entry, incorporating all key attributes.

        Returns:
            str: The SHA-256 hash representing this entry’s unique identity.
        """
        # Convert Timestamp to string format
        timestamp_str = self.timestamp.ToJsonString()

        entry_data = (
            f"{self.version}{self.action}{timestamp_str}{self.creator_id}"
            f"{self.contributor_id}{self.previous_hashes}{self.metadata}"
        )

        # ✅ Use HyphaCrypt for cryptographic hashing
        crypt = HyphaCrypt(data=b"", segment_id="lineage")
        entry_hash = crypt.hypha_hash(entry_data.encode())

        secure_logger.log_audit_event("debug", "LineageEntry", f"Calculated hash: {entry_hash}")

        return entry_hash

    def to_dict(self) -> Dict[str, any]:
        """
        Serializes the entry to a dictionary for storage or transmission.

        Returns:
            Dict: A dictionary representation of the lineage entry.
        """
        entry_dict = {
            "version": self.version,
            "action": self.action,
            "creator_id": self.creator_id,
            "contributor_id": self.contributor_id,
            "timestamp": self.timestamp.ToJsonString(),  # ✅ Convert Timestamp to JSON string
            "previous_hashes": self.previous_hashes,
            "metadata": self.metadata,
            "entry_hash": self.entry_hash,  # Include computed hash for integrity tracking
        }
        secure_logger.log_audit_event("debug", "LineageEntry", f"Serialized to dict: {entry_dict}")

        return entry_dict

    @classmethod
    def from_dict(cls, entry_dict: Dict[str, any]) -> "LineageEntry":
        """
        Creates a LineageEntry instance from a dictionary.

        Args:
            entry_dict (Dict): A dictionary representation of a lineage entry.

        Returns:
            LineageEntry: A new instance of LineageEntry based on the dictionary data.
        """
        try:
            instance = cls(
                version=entry_dict["version"],
                action=entry_dict["action"],
                creator_id=entry_dict["creator_id"],
                contributor_id=entry_dict["contributor_id"],
                previous_hashes=entry_dict.get("previous_hashes", []),
                metadata=entry_dict.get("metadata", {}),
            )

            # ✅ Convert timestamp from JSON string back to Protobuf format
            instance.timestamp = from_json_string_to_protobuf(entry_dict["timestamp"])

            # ✅ Verify hash consistency
            computed_hash = instance.calculate_hash()
            if computed_hash != entry_dict["entry_hash"]:
                secure_logger.log_audit_event(
                    "error",
                    "LineageEntry",
                    f"Hash mismatch detected! Expected: {entry_dict['entry_hash']}, Computed: {computed_hash}",
                )
                raise ValueError("Hash mismatch: possible tampering detected!")

            secure_logger.log_audit_event(
                "info", "LineageEntry", f"Recreated LineageEntry from dict."
            )

            return instance

        except KeyError as e:
            secure_logger.log_audit_event("error", "LineageEntry", f"Missing required field: {e}")
            raise ValueError(f"Missing required field: {e}") from e
