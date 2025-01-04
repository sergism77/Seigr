# src/immune_system/adaptive_monitoring.py

import logging

from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata
from src.immune_system.integrity_monitoring import immune_ping
from src.immune_system.threat_detection import ThreatDetector
from src.replication.replication_controller import ReplicationController

logger = logging.getLogger(__name__)


class AdaptiveMonitor:
    def __init__(
        self,
        replication_controller: ReplicationController,
        threat_detector: ThreatDetector,
        critical_threshold: int = 10,
    ):
        """
        Initializes the AdaptiveMonitor for continuous monitoring and adaptive replication.

        Args:
            replication_controller (ReplicationController): Controller to handle replication requests.
            threat_detector (ThreatDetector): Detector to log and escalate threats.
            critical_threshold (int): Threshold for high-severity replication escalation.
        """
        self.replication_controller = replication_controller
        self.threat_detector = threat_detector
        self.critical_threshold = critical_threshold

    def monitor_segment(self, segment_metadata: SegmentMetadata, data: bytes) -> bool:
        """
        Monitors a segment's integrity and adapts replication if necessary.

        Args:
            segment_metadata (SegmentMetadata): Metadata of the segment being monitored.
            data (bytes): Data of the segment for integrity checks.

        Returns:
            bool: True if the segment passed integrity check, False otherwise.
        """
        segment_hash = segment_metadata.segment_hash
        logger.debug(f"Monitoring segment {segment_hash} with adaptive monitoring.")

        # Check the segment integrity
        is_valid = immune_ping(segment_metadata, data)
        if not is_valid:
            logger.warning(
                f"Integrity check failed for segment {segment_hash}. Recording threat and handling replication."
            )
            self.threat_detector.record_threat(segment_metadata)
            self._handle_adaptive_replication(segment_hash)
            return False

        logger.info(f"Segment {segment_hash} passed integrity check.")
        return True

    def _handle_adaptive_replication(self, segment_hash: str):
        """
        Manages replication based on the current threat level of a segment.

        Args:
            segment_hash (str): Hash of the segment to assess for replication.
        """
        threat_count = self.threat_detector.get_threat_count(segment_hash)

        if threat_count >= self.critical_threshold:
            logger.critical(
                f"Critical threat level reached for segment {segment_hash}. Initiating critical replication."
            )
            self.replication_controller.trigger_critical_replication(segment_hash)
        elif threat_count >= self.threat_detector.adaptive_threshold:
            logger.warning(
                f"High threat level for segment {segment_hash}. Initiating adaptive replication."
            )
            self.replication_controller.trigger_adaptive_replication(
                segment_hash, threat_level=5
            )
        elif threat_count >= 3:
            logger.info(
                f"Moderate threat level for segment {segment_hash}. Initiating security replication."
            )
            self.replication_controller.trigger_security_replication(segment_hash)
        else:
            logger.debug(
                f"Low threat level for segment {segment_hash}. No adaptive replication needed."
            )

    def run_monitoring_cycle(self, segments_status: dict):
        """
        Runs a full monitoring cycle for all segments in the system.

        Args:
            segments_status (dict): A dictionary containing metadata and data for each segment.
        """
        for segment_hash, status in segments_status.items():
            segment_metadata = status.get("segment_metadata")
            data = status.get("data")

            if not segment_metadata or data is None:
                logger.warning(
                    f"Missing metadata or data for segment {segment_hash}. Skipping."
                )
                continue

            self.monitor_segment(segment_metadata, data)

    def escalate_critical_segments(self):
        """
        Escalates all segments that have reached the critical threat level, triggering necessary replication.
        """
        high_risk_segments = self.threat_detector.detect_high_risk_segments()
        for segment_hash in high_risk_segments:
            logger.critical(
                f"Segment {segment_hash} is high risk. Triggering urgent replication."
            )
            self.replication_controller.trigger_critical_replication(segment_hash)

    def reset_segment_monitoring(self, segment_hash: str):
        """
        Resets the monitoring and threat count for a specific segment after action is taken.

        Args:
            segment_hash (str): Hash of the segment to reset.
        """
        logger.info(f"Resetting monitoring for segment {segment_hash}.")
        self.threat_detector.reset_threat_count(segment_hash)
