# src/immune_system/rollback_handling.py

import logging
from dot_seigr.core.seigr_file import SeigrFile
from dot_seigr.capsule.seigr_integrity import verify_segment_integrity
from src.dot_seigr.rollback import rollback_to_previous_state
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

def rollback_segment(seigr_file: SeigrFile) -> bool:
    """
    Rolls back a segment to a previous secure state if threats are detected.

    Args:
        seigr_file (SeigrFile): The SeigrFile object representing the segment to rollback.

    Returns:
        bool: True if rollback was successful, False otherwise.
    """
    try:
        if not seigr_file.temporal_layers:
            logger.warning(f"No temporal layers available for rollback on segment {seigr_file.hash}.")
            return False

        # Rollback to previous state
        rollback_to_previous_state(seigr_file)
        logger.info(f"Successfully rolled back segment {seigr_file.hash} to a secure state.")
        return True
    except Exception as e:
        logger.error(f"Failed to rollback segment {seigr_file.hash}: {e}")
        return False
    
class RollbackHandler:
    def __init__(self):
        """
        Initializes the RollbackHandler, which manages segment rollbacks when integrity issues are detected.
        """
        self.rollback_log = []

    def verify_rollback_availability(self, seigr_file: SeigrFile) -> bool:
        """
        Checks if a rollback can be performed by verifying the existence of previous secure states.

        Args:
            seigr_file (SeigrFile): The segment file object to check for rollback availability.

        Returns:
            bool: True if rollback is possible, False otherwise.
        """
        has_layers = len(seigr_file.temporal_layers) > 1
        logger.debug(f"Rollback availability for segment {seigr_file.hash}: {has_layers}")
        return has_layers

    def rollback_to_previous_state(self, seigr_file: SeigrFile) -> bool:
        """
        Attempts to roll back a segment to its last secure state.

        Args:
            seigr_file (SeigrFile): The segment file object to roll back.

        Returns:
            bool: True if rollback succeeded, False otherwise.
        """
        if not self.verify_rollback_availability(seigr_file):
            logger.warning(f"No previous layers available for rollback on segment {seigr_file.hash}. Rollback aborted.")
            return False

        # Retrieve the last secure temporal layer
        previous_layer = seigr_file.temporal_layers[-2]

        # Verify the integrity of the previous state
        if not verify_segment_integrity(previous_layer, previous_layer.data_snapshot["data"]):
            logger.error(f"Integrity verification failed for previous layer at {previous_layer.timestamp}. Rollback aborted.")
            return False

        # Perform the rollback by restoring the previous layer's data and metadata
        self._revert_segment_data(seigr_file, previous_layer)
        self._log_rollback_event(seigr_file.hash, previous_layer.timestamp)

        logger.info(f"Rollback successful for segment {seigr_file.hash}. Reverted to timestamp {previous_layer.timestamp}.")
        return True

    def _revert_segment_data(self, seigr_file: SeigrFile, previous_layer) -> None:
        """
        Replaces the segment’s current data and metadata with those from the previous secure state.

        Args:
            seigr_file (SeigrFile): The segment file object to revert.
            previous_layer: The temporal layer object representing the previous secure state.
        """
        # Restore data and update segment hash
        seigr_file.data = previous_layer.data_snapshot["data"]
        seigr_file.hash = previous_layer.layer_hash

        # Restore metadata (e.g., links, coordinates)
        self._restore_metadata(seigr_file, previous_layer)

        # Add a temporal layer reflecting the rollback state
        seigr_file.add_temporal_layer()
        logger.debug(f"Segment {seigr_file.hash} reverted to previous state with hash {previous_layer.layer_hash}.")

    def _restore_metadata(self, seigr_file: SeigrFile, previous_layer) -> None:
        """
        Restores the segment metadata from the previous layer.

        Args:
            seigr_file (SeigrFile): The segment file object.
            previous_layer: The temporal layer object with metadata to restore.
        """
        # Restore primary and secondary links
        seigr_file.metadata.primary_link = previous_layer.data_snapshot["primary_link"]
        seigr_file.metadata.secondary_links = previous_layer.data_snapshot["secondary_links"]

        # Restore additional metadata (if applicable)
        if "coordinate_index" in previous_layer.data_snapshot:
            seigr_file.metadata.coordinate_index = previous_layer.data_snapshot["coordinate_index"]

    def _log_rollback_event(self, segment_hash: str, timestamp: datetime) -> None:
        """
        Logs the rollback event for auditing purposes.

        Args:
            segment_hash (str): The hash of the segment that was rolled back.
            timestamp (datetime): The timestamp of the secure state rolled back to.
        """
        rollback_entry = {
            "segment_hash": segment_hash,
            "timestamp": timestamp.isoformat(),
            "rollback_time": datetime.now(timezone.utc).isoformat()
        }
        self.rollback_log.append(rollback_entry)

        # Enforce a maximum rollback log size
        max_log_size = 500
        if len(self.rollback_log) > max_log_size:
            self.rollback_log.pop(0)

        logger.info(f"Rollback event logged for segment {segment_hash} at {timestamp}.")

    def rollback_if_needed(self, seigr_file: SeigrFile) -> bool:
        """
        Attempts to perform a rollback on a segment if integrity checks fail.

        Args:
            seigr_file (SeigrFile): The segment file object to check and possibly roll back.

        Returns:
            bool: True if rollback was successful, False otherwise.
        """
        if not verify_segment_integrity(seigr_file.metadata, seigr_file.data):
            logger.warning(f"Integrity check failed for segment {seigr_file.hash}. Initiating rollback.")
            return self.rollback_to_previous_state(seigr_file)
        else:
            logger.info(f"Segment {seigr_file.hash} integrity verified; no rollback needed.")
            return False
