# src/dot_seigr/lineage/lineage.py

import logging
from typing import Dict, List, Optional

from google.protobuf.timestamp_pb2 import Timestamp
from datetime import datetime, timezone

from .lineage_entry import LineageEntry
from .lineage_integrity import LineageIntegrity
from .lineage_storage import LineageStorage
from src.crypto.hypha_crypt import HyphaCrypt  # Ensuring proper hash computation
from src.logger.secure_logger import secure_logger

class Lineage:
    """
    Manages a sequence of lineage entries, providing functionality for adding entries,
    verifying integrity, and saving/loading lineage data to/from disk.
    """

    def __init__(self, creator_id: str, initial_hash: Optional[str] = None, version: str = "1.0"):
        """
        Initializes the Lineage instance to manage lineage entries and integrity.

        Args:
            creator_id (str): Unique identifier for the creator.
            initial_hash (Optional[str]): Initial hash for starting the lineage chain.
            version (str): Version identifier for the lineage format.
        """
        self.creator_id = creator_id
        self.entries: List[Dict] = []
        self.version = version
        self.current_hash = initial_hash or self._compute_initial_hash()
        self.integrity_checker = LineageIntegrity()

        secure_logger.log_audit_event(
            "info", "Lineage", f"✅ Initialized Lineage for creator {self.creator_id}, version {self.version}"
        )

    def add_entry(
        self,
        action: str,
        contributor_id: str,
        previous_hashes: Optional[List[str]] = None,
        metadata: Optional[Dict] = None,
    ) -> None:
        """
        Adds an entry to the lineage with details of the action, contributor, and metadata.

        Args:
            action (str): Action performed, e.g., "create", "modify".
            contributor_id (str): ID of the contributor performing the action.
            previous_hashes (Optional[List[str]]): List of hashes from previous entries.
            metadata (Optional[Dict]): Additional metadata related to the action.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        if not action or not contributor_id:
            raise ValueError(
                "❌ Action and contributor_id are required for adding a lineage entry."
            )

        # Set default previous_hash to current hash if none is provided
        previous_hashes = previous_hashes or [self.current_hash]

        # Convert timestamp to Protobuf Timestamp format
        timestamp_proto = Timestamp()
        timestamp_proto.FromDatetime(datetime.now(timezone.utc))

        entry = LineageEntry(
            version=self.version,
            action=action,
            creator_id=self.creator_id,
            contributor_id=contributor_id,
            previous_hashes=previous_hashes,
            metadata=metadata,
        )

        # Update current hash after adding entry
        self.current_hash = entry.calculate_hash()
        self.entries.append(entry.to_dict())

        secure_logger.log_audit_event(
            "info", "Lineage", 
            f"✅ Added lineage entry with action '{action}' by contributor '{contributor_id}'. Updated hash: {self.current_hash}"
        )

    def save_to_disk(self, storage_path: str) -> bool:
        """
        Saves the current lineage to disk as a serialized file.

        Args:
            storage_path (str): Path where lineage data will be saved.

        Returns:
            bool: True if saved successfully, False otherwise.
        """
        try:
            LineageStorage.save_to_disk(self, storage_path)
            secure_logger.log_audit_event("info", "LineageStorage", f"✅ Lineage data saved to {storage_path}")
            return True
        except IOError as e:
            secure_logger.log_audit_event("error", "LineageStorage", f"❌ Failed to save lineage data to {storage_path}: {e}")
            return False

    def load_from_disk(self, storage_path: str) -> bool:
        """
        Loads lineage data from disk and updates current instance state.

        Args:
            storage_path (str): Path from where lineage data will be loaded.

        Returns:
            bool: True if loaded successfully, False otherwise.
        """
        try:
            loaded_lineage = LineageStorage.load_from_disk(storage_path)
            self.creator_id = loaded_lineage["creator_id"]
            self.current_hash = loaded_lineage["current_hash"]
            self.version = loaded_lineage["version"]
            self.entries = loaded_lineage["entries"]
            secure_logger.log_audit_event("info", "LineageStorage", f"✅ Lineage data loaded from {storage_path}")
            return True
        except (IOError, ValueError) as e:
            secure_logger.log_audit_event("error", "LineageStorage", f"❌ Failed to load lineage data from {storage_path}: {e}")
            return False

    def verify_integrity(self, reference_hash: str) -> bool:
        """
        Verifies the integrity of the lineage by comparing hashes.

        Args:
            reference_hash (str): Expected hash to verify lineage integrity.

        Returns:
            bool: True if integrity check passes, False otherwise.
        """
        is_valid = self.integrity_checker.verify_integrity(self.current_hash, reference_hash)

        if is_valid:
            secure_logger.log_audit_event("info", "Lineage", "✅ Lineage integrity verified successfully.")
        else:
            secure_logger.log_audit_event("warning", "Lineage", "⚠️ Lineage integrity verification failed.")
        return is_valid

    def ping_activity(self) -> Timestamp:
        """
        Tracks activity by updating the last ping timestamp in the lineage.

        Returns:
            Timestamp: The Protobuf Timestamp of the ping.
        """
        timestamp_proto = Timestamp()
        timestamp_proto.FromDatetime(datetime.now(timezone.utc))

        secure_logger.log_audit_event("info", "Lineage", f"🔵 Ping activity updated: {timestamp_proto.ToJsonString()}")
        return timestamp_proto

    def list_entries(self) -> List[Dict]:
        """
        Returns a list of all entries in the lineage for inspection or audit.

        Returns:
            List[Dict]: A list of dictionaries representing each lineage entry.
        """
        secure_logger.log_audit_event("debug", "Lineage", "📜 Listing all lineage entries.")
        return self.entries

    def update_lineage_hash(self) -> None:
        """
        Recomputes the current hash based on the latest entry in the lineage.
        """
        if self.entries:
            last_entry = self.entries[-1]
            self.current_hash = LineageEntry.from_dict(last_entry).calculate_hash()
            secure_logger.log_audit_event("debug", "Lineage", f"🔄 Updated current lineage hash to: {self.current_hash}")

    def get_current_hash(self) -> str:
        """
        Returns the current hash of the lineage.

        Returns:
            str: Current hash representing the latest lineage state.
        """
        return self.current_hash

    def _compute_initial_hash(self) -> str:
        """
        Generates an initial hash for the lineage based on creator ID and timestamp.

        Returns:
            str: Initial SHA-256 hash for lineage.
        """
        crypt = HyphaCrypt(data=b"", segment_id="lineage")
        initial_data = f"{self.creator_id}_{datetime.now(timezone.utc).isoformat()}"
        initial_hash = crypt.hypha_hash(initial_data.encode())

        secure_logger.log_audit_event("debug", "Lineage", f"🛠 Generated initial hash for lineage: {initial_hash}")
        return initial_hash
