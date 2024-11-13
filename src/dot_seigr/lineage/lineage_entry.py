from datetime import datetime, timezone
from typing import List, Dict, Optional
from src.crypto.hypha_crypt import hypha_hash
import logging

logger = logging.getLogger(__name__)

class LineageEntry:
    """
    Represents a lineage entry capturing metadata and hash information about a specific
    lineage event, allowing for version tracking and integrity verification.
    """

    def __init__(self, 
                 version: str, 
                 action: str, 
                 creator_id: str, 
                 contributor_id: str, 
                 previous_hashes: Optional[List[str]] = None, 
                 metadata: Optional[Dict] = None):
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
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.previous_hashes = previous_hashes or []
        self.metadata = metadata or {}

        # Validation on initialization
        self._validate_fields()
        logger.info(f"Initialized LineageEntry: {self.to_dict()}")

    def _validate_fields(self):
        """Ensures that essential fields are properly initialized."""
        if not self.version or not self.action or not self.creator_id or not self.contributor_id:
            logger.error("LineageEntry initialization failed due to missing required fields.")
            raise ValueError("version, action, creator_id, and contributor_id are required fields.")
        logger.debug("All required fields for LineageEntry are valid.")

    def calculate_hash(self) -> str:
        """
        Calculates and returns the hash of the entry, incorporating all key attributes.

        Returns:
            str: The SHA-256 hash representing this entry’s unique identity.
        """
        entry_data = f"{self.version}{self.action}{self.timestamp}{self.creator_id}" \
                     f"{self.contributor_id}{self.previous_hashes}{self.metadata}"
        entry_hash = hypha_hash(entry_data.encode())
        logger.debug(f"Calculated hash for LineageEntry: {entry_hash}")
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
            "timestamp": self.timestamp,
            "previous_hashes": self.previous_hashes,
            "metadata": self.metadata
        }
        logger.debug(f"Serialized LineageEntry to dict: {entry_dict}")
        return entry_dict

    @classmethod
    def from_dict(cls, entry_dict: Dict[str, any]) -> 'LineageEntry':
        """
        Creates a LineageEntry instance from a dictionary.

        Args:
            entry_dict (Dict): A dictionary representation of a lineage entry.

        Returns:
            LineageEntry: A new instance of LineageEntry based on the dictionary data.
        """
        instance = cls(
            version=entry_dict["version"],
            action=entry_dict["action"],
            creator_id=entry_dict["creator_id"],
            contributor_id=entry_dict["contributor_id"],
            previous_hashes=entry_dict.get("previous_hashes", []),
            metadata=entry_dict.get("metadata", {})
        )
        logger.info(f"Created LineageEntry from dict: {entry_dict}")
        return instance
