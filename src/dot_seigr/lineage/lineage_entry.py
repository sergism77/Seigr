from datetime import datetime, timezone
from src.crypto.hypha_crypt import hypha_hash

class LineageEntry:
    def __init__(self, version: str, action: str, creator_id: str, contributor_id: str, previous_hashes=None, metadata=None):
        self.version = version
        self.action = action
        self.creator_id = creator_id
        self.contributor_id = contributor_id
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.previous_hashes = previous_hashes or []
        self.metadata = metadata or {}

    def calculate_hash(self) -> str:
        """
        Calculates and returns the hash of the entry for lineage consistency.
        """
        entry_data = f"{self.action}{self.timestamp}{self.previous_hashes}".encode()
        return hypha_hash(entry_data)

    def to_dict(self) -> dict:
        """
        Returns the entry as a dictionary for easy serialization.
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
