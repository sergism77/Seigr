# src/dot_seigr/lineage/lineage_manager.py

import logging
from typing import Dict, List, Optional, Union

from .lineage import Lineage
from .lineage_integrity import LineageIntegrity
from .lineage_serializer import LineageSerializer
from .lineage_storage import LineageStorage
from src.logger.secure_logger import secure_logger

class LineageManager:
    """
    Manages the high-level operations for lineage tracking within the Seigr framework.
    Provides functions for adding entries, validating lineage integrity, managing storage,
    and ensuring future compatibility through a modular, extensible design.
    """

    def __init__(self, creator_id: str, initial_hash: Optional[str] = None, version: str = "1.0"):
        """
        Initializes the LineageManager, either creating a new lineage or loading an existing one.

        Args:
            creator_id (str): Unique identifier for the lineage creator.
            initial_hash (Optional[str]): Initial hash for lineage continuity, if any.
            version (str): Version identifier for the lineage format, for compatibility tracking.
        """
        self.creator_id = creator_id
        self.lineage = Lineage(creator_id, initial_hash=initial_hash, version=version)
        self.integrity_checker = LineageIntegrity()

        secure_logger.log_audit_event("info", "LineageManager", f"Initialized LineageManager for creator {creator_id}, version {version}")

    def add_lineage_entry(
        self,
        action: str,
        contributor_id: str,
        metadata: Optional[Dict] = None,
        previous_hashes: Optional[List[str]] = None,
    ) -> bool:
        """
        Adds a new entry to the lineage with provided action details.

        Args:
            action (str): Action type (e.g., "create", "update").
            contributor_id (str): ID of the contributor performing the action.
            metadata (Optional[Dict]): Metadata dictionary with additional entry details.
            previous_hashes (Optional[List[str]]): List of previous hashes for continuity.

        Returns:
            bool: True if entry added successfully, False otherwise.
        """
        try:
            self.lineage.add_entry(
                action=action,
                contributor_id=contributor_id,
                previous_hashes=previous_hashes or [self.lineage.current_hash],
                metadata=metadata or {},
            )
            secure_logger.log_audit_event("info", "LineageManager", f"✅ Lineage entry added: action '{action}' by contributor '{contributor_id}'")
            self.update_lineage_hash()
            return True
        except ValueError as e:
            secure_logger.log_audit_event("error", "LineageManager", f"❌ Failed to add lineage entry: {e}")
            return False

    def validate_lineage_integrity(self) -> bool:
        """
        Validates the entire lineage by ensuring hash continuity across entries.

        Returns:
            bool: True if lineage integrity is intact, False otherwise.
        """
        reference_hash = self.lineage.current_hash
        is_valid = self.integrity_checker.verify_full_lineage_integrity(
            self.lineage.entries, reference_hash
        )

        if is_valid:
            secure_logger.log_audit_event("info", "LineageManager", "✅ Lineage integrity verified successfully.")
        else:
            secure_logger.log_audit_event("warning", "LineageManager", "⚠️ Lineage integrity verification failed.")
        return is_valid

    def save_lineage(self, storage_path: str) -> bool:
        """
        Saves the current lineage state to disk.

        Args:
            storage_path (str): Path to save the serialized lineage file.

        Returns:
            bool: True if the lineage is saved successfully, False otherwise.
        """
        try:
            LineageStorage.save_to_disk(self.lineage, storage_path)
            secure_logger.log_audit_event("info", "LineageManager", f"✅ Lineage successfully saved at {storage_path}")
            return True
        except IOError as e:
            secure_logger.log_audit_event("error", "LineageManager", f"❌ Error saving lineage to disk at {storage_path}: {e}")
            return False

    def load_lineage(self, storage_path: str) -> bool:
        """
        Loads a lineage from disk into the current manager state.

        Args:
            storage_path (str): Path to the stored lineage file.

        Returns:
            bool: True if loaded successfully, False otherwise.
        """
        try:
            loaded_data = LineageStorage.load_from_disk(storage_path)
            self.lineage = Lineage(
                creator_id=loaded_data["creator_id"],
                initial_hash=loaded_data["current_hash"],
                version=loaded_data["version"],
            )
            self.lineage.entries = loaded_data["entries"]
            secure_logger.log_audit_event("info", "LineageManager", f"✅ Lineage loaded from {storage_path}")
            return True
        except (IOError, ValueError) as e:
            secure_logger.log_audit_event("error", "LineageManager", f"❌ Failed to load lineage from {storage_path}: {e}")
            return False

    def list_entries(self) -> List[Dict[str, Union[str, int]]]:
        """
        Retrieves all entries in the lineage for inspection or auditing.

        Returns:
            List[Dict[str, Union[str, int]]]: List of dictionaries representing each lineage entry.
        """
        entries = self.lineage.list_entries()
        secure_logger.log_audit_event("debug", "LineageManager", f"🔍 Listing {len(entries)} lineage entries.")
        return entries

    def update_lineage_hash(self):
        """
        Updates the current lineage hash based on the latest entry.
        """
        self.lineage.update_lineage_hash()
        secure_logger.log_audit_event("debug", "LineageManager", f"🔄 Lineage hash updated to {self.lineage.current_hash}")

    def record_activity_ping(self):
        """
        Records a timestamped activity ping, useful for tracking and monitoring.
        """
        self.lineage.ping_activity()
        secure_logger.log_audit_event("debug", "LineageManager", "🟢 Activity ping recorded.")

    def export_lineage_to_protobuf(self) -> bytes:
        """
        Exports the lineage to Protobuf format.

        Returns:
            bytes: Serialized Protobuf data representing the lineage.
        """
        try:
            protobuf_data = LineageSerializer.to_protobuf(self.lineage).SerializeToString()
            secure_logger.log_audit_event("info", "LineageManager", "✅ Lineage exported to Protobuf format.")
            return protobuf_data
        except Exception as e:
            secure_logger.log_audit_event("error", "LineageManager", f"❌ Error exporting lineage to Protobuf format: {e}")
            raise

    def import_lineage_from_protobuf(self, protobuf_data: bytes):
        """
        Imports lineage data from Protobuf format.

        Args:
            protobuf_data (bytes): Protobuf data to deserialize into the lineage.
        """
        try:
            lineage_data = LineageSerializer.from_protobuf(protobuf_data)
            self.lineage.creator_id = lineage_data["creator_id"]
            self.lineage.current_hash = lineage_data["current_hash"]
            self.lineage.version = lineage_data["version"]
            self.lineage.entries = lineage_data["entries"]
            secure_logger.log_audit_event("info", "LineageManager", "✅ Lineage imported from Protobuf format.")
        except ValueError as e:
            secure_logger.log_audit_event("error", "LineageManager", f"❌ Failed to import lineage from Protobuf: {e}")
            raise ValueError("Protobuf data is invalid for lineage import.") from e
