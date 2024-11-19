# src/immune_system/threat_detection.py

import logging
from datetime import datetime, timezone
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata
from src.replication.replication_controller import ReplicationController
from collections import defaultdict

logger = logging.getLogger(__name__)


class ThreatDetector:
    def __init__(
        self,
        replication_controller: ReplicationController,
        adaptive_threshold: int = 5,
        max_threat_log_size: int = 1000,
    ):
        """
        Initializes the ThreatDetector for managing threat detection, logging, and escalation.

        Args:
            replication_controller (ReplicationController): Controller to handle replication when threats are detected.
            adaptive_threshold (int): Threshold to trigger adaptive replication for high-risk segments.
            max_threat_log_size (int): Maximum number of threat logs to keep.
        """
        self.replication_controller = replication_controller
        self.adaptive_threshold = adaptive_threshold
        self.max_threat_log_size = max_threat_log_size
        self.threat_log = []
        self.threat_counts = defaultdict(int)

    def record_threat(self, segment_metadata: SegmentMetadata):
        """
        Records a threat instance, updating the log and counting occurrences for each segment.

        Args:
            segment_metadata (SegmentMetadata): Metadata of the segment where a threat is detected.
        """
        segment_hash = segment_metadata.segment_hash
        threat_entry = {
            "segment_hash": segment_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Update the threat log and threat counts
        self.threat_log.append(threat_entry)
        self.threat_counts[segment_hash] += 1

        # Enforce log size limit
        if len(self.threat_log) > self.max_threat_log_size:
            self.threat_log.pop(0)

        logger.info(
            f"Threat recorded for segment {segment_hash}. Total threats for this segment: {self.threat_counts[segment_hash]}"
        )
        self._handle_threat_escalation(segment_hash)

    def _handle_threat_escalation(self, segment_hash: str):
        """
        Handles escalation based on the number of threats recorded for a segment.

        Args:
            segment_hash (str): Unique hash identifying the segment under potential threat.
        """
        threat_count = self.threat_counts[segment_hash]

        # Trigger adaptive replication if threshold is exceeded
        if threat_count >= self.adaptive_threshold:
            logger.critical(
                f"Adaptive threshold exceeded for segment {segment_hash} ({threat_count} threats). Initiating adaptive replication."
            )
            self.replication_controller.trigger_adaptive_replication(
                segment_hash, threat_level=5
            )
        elif threat_count >= 3:
            logger.warning(
                f"Security replication triggered for segment {segment_hash} due to high threat count: {threat_count}"
            )
            self.replication_controller.trigger_security_replication(segment_hash)
        else:
            logger.info(
                f"Threat level for segment {segment_hash} is under control with threat count: {threat_count}."
            )

    def detect_high_risk_segments(self) -> list:
        """
        Identifies segments that have a high count of threats.

        Returns:
            list: A list of high-risk segment hashes.
        """
        high_risk_segments = [
            segment_hash
            for segment_hash, count in self.threat_counts.items()
            if count >= self.adaptive_threshold
        ]
        logger.info(f"High-risk segments identified: {high_risk_segments}")
        return high_risk_segments

    def reset_threat_count(self, segment_hash: str):
        """
        Resets the threat count for a specified segment after action has been taken.

        Args:
            segment_hash (str): Unique hash identifying the segment to reset.
        """
        if segment_hash in self.threat_counts:
            logger.info(f"Resetting threat count for segment {segment_hash}.")
            self.threat_counts[segment_hash] = 0

    def monitor_and_escalate(self):
        """
        Scans through the current threat counts and escalates any segment that reaches critical thresholds.
        """
        for segment_hash in self.detect_high_risk_segments():
            logger.critical(
                f"Segment {segment_hash} has exceeded the adaptive threshold. Initiating critical replication."
            )
            self.replication_controller.trigger_critical_replication(segment_hash)

    def get_threat_count(self, segment_hash: str) -> int:
        """
        Retrieves the current threat count for a given segment.

        Args:
            segment_hash (str): Unique hash identifying the segment.

        Returns:
            int: Number of threats recorded for this segment.
        """
        return self.threat_counts.get(segment_hash, 0)
