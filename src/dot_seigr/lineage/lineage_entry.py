from datetime import datetime, timezone
from typing import List, Dict, Optional
from src.crypto.hypha_crypt import hypha_hash

class LineageEntry:
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

    def _validate_fields(self):
        """Ensures that essential fields are properly initialized."""
        if not self.version or not self.action or not self.creator_id or not self.contributor_id:
            raise ValueError("version, action, creator_id, and contributor_id are required fields.")

    def calculate_hash(self) -> str:
        """
        Calculates and returns the hash of the entry, incorporating all key attributes.

        Returns:
            str: The SHA-256 hash representing this entry’s unique identity.
        """
        entry_data = f"{self.version}{self.action}{self.timestamp}{self.creator_id}" \
                     f"{self.contributor_id}{self.previous_hashes}{self.metadata}"
        return hypha_hash(entry_data.encode())

    def to_dict(self) -> Dict:
        """
        Serializes the entry to a dictionary for storage or transmission.

        Returns:
            Dict: A dictionary representation of the lineage entry.
        """
        return {
            "version": self.version,
            "action": self.action,
            "creator_id": self.creator_id,
            "contributor_id": self.contributor_id,
            "timestamp": self.timestamp,
            "previous_hashes": self.previous_hashes,
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, entry_dict: Dict) -> 'LineageEntry':
        """
        Creates a LineageEntry instance from a dictionary.

        Args:
            entry_dict (Dict): A dictionary representation of a lineage entry.

        Returns:
            LineageEntry: A new instance of LineageEntry based on the dictionary data.
        """
        return cls(
            version=entry_dict["version"],
            action=entry_dict["action"],
            creator_id=entry_dict["creator_id"],
            contributor_id=entry_dict["contributor_id"],
            previous_hashes=entry_dict.get("previous_hashes", []),
            metadata=entry_dict.get("metadata", {})
        )
