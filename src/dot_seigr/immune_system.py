import logging
from datetime import datetime, timezone
from src.dot_seigr.integrity import verify_segment_integrity
from src.dot_seigr.replication_controller import ReplicationController
from src.dot_seigr.rollback import rollback_to_previous_state, verify_rollback_availability
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata
from src.dot_seigr.seigr_file import SeigrFile

logger = logging.getLogger(__name__)

class ImmuneSystem:
    def __init__(self, monitored_segments, replication_controller, replication_threshold=3, adaptive_threshold=5, max_threat_log_size=1000):
        """
        Initializes the Immune System with monitored segments, thresholds, and logging limits.
        """
        self.monitored_segments = monitored_segments
        self.replication_controller = replication_controller
        self.threat_log = []
        self.replication_threshold = replication_threshold
        self.adaptive_threshold = adaptive_threshold
        self.max_threat_log_size = max_threat_log_size

    def immune_ping(self, segment_metadata: SegmentMetadata, data: bytes) -> bool:
        """
        Sends an integrity ping, performing multi-layered hash verification on a segment.
        """
        segment_hash = segment_metadata.segment_hash
        logger.debug(f"Starting immune_ping on segment {segment_hash} with provided data.")

        is_valid = verify_segment_integrity(segment_metadata, data)
        logger.debug(f"Integrity check for segment {segment_hash} returned: {is_valid}")

        if not is_valid:
            logger.warning(f"Integrity check failed for segment {segment_hash}. Recording threat.")
            self.record_threat(segment_hash)
            self.handle_threat_response(segment_hash)

        return is_valid

    def monitor_integrity(self):
        """
        Continuously monitors the integrity of all segments in `monitored_segments`.
        """
        for segment_metadata in self.monitored_segments.values():
            data = b""  # Placeholder; in practice, retrieve or mock the actual data.
            self.immune_ping(segment_metadata, data)

    def record_threat(self, segment_hash: str):
        """
        Records a threat instance and manages threat log size.
        """
        threat_entry = {
            "segment_hash": segment_hash,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.threat_log.append(threat_entry)

        # Enforce log size limit
        if len(self.threat_log) > self.max_threat_log_size:
            self.threat_log.pop(0)

        logger.info(f"Threat recorded for segment {segment_hash}. Total logged threats: {len(self.threat_log)}")

    def detect_high_risk_segments(self):
        """
        Analyzes the threat log to identify high-risk segments with multiple failures.
        """
        threat_counts = self._get_threat_counts()
        high_risk_segments = [
            seg for seg, count in threat_counts.items() if count >= self.adaptive_threshold
        ]
        logger.info(f"High-risk segments identified: {high_risk_segments}")
        return high_risk_segments

    def handle_threat_response(self, segment_hash: str):
        """
        Manages responses to a detected threat, initiating replication or rollback as appropriate.
        """
        high_risk_segments = self.detect_high_risk_segments()

        if segment_hash in high_risk_segments:
            logger.warning(f"High-risk segment {segment_hash} detected; initiating adaptive replication.")
            self.replication_controller.threat_replicator.adaptive_threat_replication(
                segment=segment_hash, threat_level=5, min_replication=self.replication_controller.min_replication
            )
        elif self._get_segment_threat_count(segment_hash) >= self.replication_threshold:
            logger.info(f"Threshold for basic replication met for segment {segment_hash}. Initiating security replication.")
            self.replication_controller.trigger_security_replication(segment_hash)
        else:
            logger.info(f"Segment {segment_hash} remains under regular monitoring with no immediate replication action.")

    def rollback_segment(self, seigr_file: SeigrFile):
        """
        Rolls back a segment to its last verified secure state if threats are detected.
        """
        # Check for available temporal layers
        if not seigr_file.temporal_layers:
            logger.warning(f"No previous layers available for rollback on segment {seigr_file.hash}. Skipping rollback.")
            return

        # Log the current temporal layers and hash for debugging
        logger.debug(f"Debug: Temporal layers available for segment {seigr_file.hash}: {[layer.layer_hash for layer in seigr_file.temporal_layers]}")
        logger.debug(f"Debug: Current segment hash = {seigr_file.hash}")

        # Check if rollback is allowed
        rollback_allowed = verify_rollback_availability(seigr_file)
        logger.debug(f"Debug: rollback_allowed for segment {seigr_file.hash} = {rollback_allowed}")

        # Perform rollback if allowed and log the call attempt
        if rollback_allowed:
            logger.info(f"Rollback allowed for segment {seigr_file.hash}, attempting rollback.")
            
            # Double-check the actual call to ensure this is executed
            try:
                rollback_to_previous_state(seigr_file)
                logger.info(f"Successfully rolled back segment {seigr_file.hash} to a secure state.")
            except Exception as e:
                logger.error(f"Error during rollback execution: {e}")
        else:
            logger.warning(f"Rollback not allowed for segment {seigr_file.hash}.")

    def adaptive_monitoring(self, critical_threshold: int):
        """
        Executes an adaptive monitoring routine, handling threats that exceed critical thresholds.
        """
        critical_segments = [
            seg for seg, count in self._get_threat_counts().items() if count >= critical_threshold
        ]

        for segment in critical_segments:
            logger.critical(f"Critical threat level reached for segment {segment}. Triggering urgent adaptive replication.")
            self.replication_controller.threat_replicator.adaptive_threat_replication(
                segment=segment, threat_level=5, min_replication=self.replication_controller.min_replication
            )

    def _get_threat_counts(self):
        """
        Internal method to count occurrences of threats per segment.
        """
        threat_counts = {}
        for entry in self.threat_log:
            threat_counts[entry["segment_hash"]] = threat_counts.get(entry["segment_hash"], 0) + 1
        return threat_counts

    def _get_segment_threat_count(self, segment_hash: str) -> int:
        """
        Returns the threat count for a specific segment.
        """
        return sum(1 for entry in self.threat_log if entry["segment_hash"] == segment_hash)
