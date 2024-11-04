import logging
import json
from datetime import datetime, timezone
from ..crypto.hypha_crypt import hypha_hash

logger = logging.getLogger(__name__)

class Lineage:
    def __init__(self, creator_id: str, initial_hash: str = None):
        """
        Initializes a Lineage instance to manage action records over time.

        Args:
            creator_id (str): ID of the lineage creator.
            initial_hash (str): Optional initial hash for existing lineage.
        """
        self.creator_id = creator_id
        self.entries = []
        self.current_hash = initial_hash or hypha_hash(creator_id.encode())
        logger.info(f"Initialized lineage for creator {creator_id} with initial hash {self.current_hash}")

    def add_entry(self, action: str, contributor_id: str):
        """
        Adds a new entry to the lineage, updates lineage hash, and appends to entries.

        Args:
            action (str): Description of the action taken.
            contributor_id (str): ID of the contributor involved.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = {
            "action": action,
            "creator_id": self.creator_id,
            "contributor_id": contributor_id,
            "timestamp": timestamp,
            "previous_hash": self.current_hash
        }
        # Update lineage hash to maintain continuity and immutability
        self.entries.append(entry)
        self.current_hash = hypha_hash(str(entry).encode())
        logger.info(f"Lineage updated for creator {self.creator_id}. New hash: {self.current_hash}")

    def load_entries(self, lineage_hash: str) -> list:
        """
        Loads lineage entries based on the provided lineage hash.
        Replace with actual retrieval logic in production.

        Args:
            lineage_hash (str): The hash identifying the lineage to load.

        Returns:
            list: A list of entries in the lineage or an empty list if not found.
        """
        logger.debug(f"Attempting to load lineage with hash: {lineage_hash}")
        # Placeholder: Return an empty list or actual data in production
        return self.entries if self.current_hash == lineage_hash else []

    def save_entries(self):
        """
        Saves the current lineage entries to persistent storage.
        Replace with storage system logic as needed.

        """
        # Placeholder: Implement persistent storage for production
        logger.info(f"Saving lineage entries for creator {self.creator_id}. Total entries: {len(self.entries)}")
        logger.debug(f"Lineage content: {self.entries}")

    def verify_integrity(self, reference_hash: str) -> bool:
        """
        Verifies lineage integrity by comparing the current hash with a reference hash.

        Args:
            reference_hash (str): Reference hash to verify against.

        Returns:
            bool: True if the hashes match, False if integrity has been compromised.
        """
        integrity_verified = self.current_hash == reference_hash
        if integrity_verified:
            logger.info(f"Integrity verified for creator {self.creator_id}. Hash: {self.current_hash}")
        else:
            logger.warning(f"Integrity check failed for creator {self.creator_id}. Expected {reference_hash}, got {self.current_hash}")
        return integrity_verified

    def export_lineage(self, filename: str) -> str:
        """
        Exports the lineage to a specified file in JSON format for further analysis.

        Args:
            filename (str): Filename to export the lineage.

        Returns:
            str: Path to the exported lineage file.
        """
        try:
            with open(filename, 'w') as f:
                json.dump({"entries": self.entries, "current_hash": self.current_hash}, f, indent=4)
            logger.info(f"Lineage exported successfully to {filename}")
            return filename
        except Exception as e:
            logger.error(f"Failed to export lineage to {filename}: {e}")
            raise
