# src/immune_system/integrity_monitoring.py

import logging
from datetime import datetime, timezone
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import SegmentMetadata
from dot_seigr.capsule.seigr_integrity import verify_segment_integrity
from src.dot_seigr.rollback import rollback_to_previous_state
from src.replication.replication_manager import ReplicationManager

logger = logging.getLogger(__name__)


def immune_ping(segment_metadata: SegmentMetadata, data: bytes) -> bool:
    """
    Sends an integrity ping, performing multi-layered hash verification on a segment.

    Args:
        segment_metadata (SegmentMetadata): Metadata of the segment to verify.
        data (bytes): Data of the segment to verify.

    Returns:
        bool: True if integrity is verified, False otherwise.
    """
    segment_hash = segment_metadata.segment_hash
    logger.debug(f"Starting immune_ping on segment {segment_hash} with provided data.")

    is_valid = verify_segment_integrity(segment_metadata, data)
    logger.debug(f"Integrity check for segment {segment_hash} returned: {is_valid}")

    if not is_valid:
        logger.warning(f"Integrity check failed for segment {segment_hash}.")

    return is_valid


class IntegrityMonitor:
    def __init__(
        self, replication_manager: ReplicationManager, monitored_segments: dict
    ):
        """
        Initializes the Integrity Monitor to handle integrity checks and track segments.

        Args:
            replication_manager (ReplicationManager): Instance managing replication requests.
            monitored_segments (dict): Dictionary of segments monitored for integrity.
        """
        self.replication_manager = replication_manager
        self.monitored_segments = monitored_segments
        self.threat_log = []

    def monitor_integrity(self):
        """
        Monitors the integrity of all segments in the monitored list.
        """
        for segment_metadata in self.monitored_segments.values():
            data = b""  # Placeholder; in practice, retrieve or mock actual data
            self.immune_ping(segment_metadata, data)

    def record_threat(self, segment_hash: str):
        """
        Records a threat and maintains a capped log of recent threats.

        Args:
            segment_hash (str): Unique hash identifying the segment with the threat.
        """
        threat_entry = {
            "segment_hash": segment_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.threat_log.append(threat_entry)

        # Enforce threat log size limit
        max_log_size = 1000  # Can be adjusted as needed
        if len(self.threat_log) > max_log_size:
            self.threat_log.pop(0)

        logger.info(
            f"Threat recorded for segment {segment_hash}. Total logged threats: {len(self.threat_log)}"
        )

    def handle_threat_response(self, segment_hash: str):
        """
        Manages threat response actions such as replication and rollback.

        Args:
            segment_hash (str): The hash of the segment requiring response.
        """
        threat_count = self.get_segment_threat_count(segment_hash)
        logger.info(
            f"Handling threat response for segment {segment_hash}, threat count: {threat_count}"
        )

        # Trigger replication if threat count exceeds a threshold
        replication_threshold = 3
        if threat_count >= replication_threshold:
            self.replication_manager.trigger_security_replication(segment_hash)
        else:
            logger.info(
                f"Segment {segment_hash} remains under regular monitoring with no immediate action."
            )

    def rollback_segment(self, segment_metadata: SegmentMetadata) -> bool:
        """
        Rolls back a segment to its last secure state if integrity checks fail.

        Args:
            segment_metadata (SegmentMetadata): Metadata of the segment.

        Returns:
            bool: True if rollback was successful, False otherwise.
        """
        if rollback_to_previous_state(segment_metadata):
            logger.info(
                f"Rollback successful for segment {segment_metadata.segment_hash}."
            )
            return True
        else:
            logger.warning(
                f"Rollback failed for segment {segment_metadata.segment_hash}."
            )
            return False

    def get_segment_threat_count(self, segment_hash: str) -> int:
        """
        Counts the number of threats recorded for a specific segment.

        Args:
            segment_hash (str): Unique hash identifying the segment.

        Returns:
            int: Number of threats recorded for this segment.
        """
        return sum(
            1 for entry in self.threat_log if entry["segment_hash"] == segment_hash
        )

    def adaptive_monitoring(self, critical_threshold: int):
        """
        Triggers adaptive replication for segments exceeding the critical threat threshold.

        Args:
            critical_threshold (int): Threat count threshold to initiate critical replication.
        """
        critical_segments = [
            seg
            for seg, count in self._get_threat_counts().items()
            if count >= critical_threshold
        ]

        for segment in critical_segments:
            logger.critical(
                f"Critical threat level reached for segment {segment}. Triggering urgent replication."
            )
            self.replication_manager.trigger_security_replication(segment)

    def _get_threat_counts(self) -> dict:
        """
        Internal method to tally threat counts for each segment.

        Returns:
            dict: A dictionary with segment hashes as keys and threat counts as values.
        """
        threat_counts = {}
        for entry in self.threat_log:
            threat_counts[entry["segment_hash"]] = (
                threat_counts.get(entry["segment_hash"], 0) + 1
            )
        return threat_counts
