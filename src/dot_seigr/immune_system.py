import logging
from datetime import datetime, timezone
from src.dot_seigr.integrity import verify_segment_integrity
from src.dot_seigr.replication import trigger_security_replication, adaptive_replication
from src.dot_seigr.rollback import rollback_to_previous_state
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata, FileMetadata
from src.dot_seigr.seigr_file import SeigrFile

logger = logging.getLogger(__name__)

class ImmuneSystem:
    def __init__(self, monitored_segments, replication_threshold=3, adaptive_threshold=5, max_threat_log_size=1000):
        """
        Initializes the immune system with monitored segments, thresholds, and logging limits.
        
        Args:
            monitored_segments (dict): Dictionary of SegmentMetadata protobufs.
            replication_threshold (int): Threshold for initiating basic replication.
            adaptive_threshold (int): Threshold for initiating adaptive replication for high-risk segments.
            max_threat_log_size (int): Maximum number of threat entries to retain for efficiency.
        """
        self.monitored_segments = monitored_segments  # Example: {segment_hash: SegmentMetadata}
        self.threat_log = []
        self.replication_threshold = replication_threshold
        self.adaptive_threshold = adaptive_threshold
        self.max_threat_log_size = max_threat_log_size

    def immune_ping(self, segment_metadata: SegmentMetadata) -> bool:
        """
        Sends an integrity ping, performing multi-layered hash verification on a segment.
        
        Args:
            segment_metadata (SegmentMetadata): Protobuf segment metadata to check.
        
        Returns:
            bool: True if integrity check passes, False if failed.
        """
        segment_hash = segment_metadata.segment_hash
        is_valid = verify_segment_integrity(segment_metadata)
        
        if not is_valid:
            self.record_threat(segment_hash)
            self.handle_threat_response(segment_hash)
        
        return is_valid

    def monitor_integrity(self):
        """
        Continuously monitors the integrity of all segments in `monitored_segments`.
        """
        for segment_metadata in self.monitored_segments.values():
            self.immune_ping(segment_metadata)

    def record_threat(self, segment_hash: str):
        """
        Records a threat instance and manages threat log size.
        
        Args:
            segment_hash (str): Hash of the segment that failed integrity.
        """
        threat_entry = {
            "segment_hash": segment_hash,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.threat_log.append(threat_entry)

        # Enforce log size limit for performance
        if len(self.threat_log) > self.max_threat_log_size:
            self.threat_log.pop(0)

        logger.info(f"Threat recorded for segment {segment_hash}. Total logged threats: {len(self.threat_log)}")

    def detect_high_risk_segments(self):
        """
        Analyzes the threat log to identify high-risk segments with multiple failures.
        
        Returns:
            list: Segments flagged for high-risk adaptive replication.
        """
        threat_counts = {}
        for entry in self.threat_log:
            threat_counts[entry["segment_hash"]] = threat_counts.get(entry["segment_hash"], 0) + 1

        high_risk_segments = [
            seg for seg, count in threat_counts.items() if count >= self.adaptive_threshold
        ]
        logger.info(f"High-risk segments identified: {high_risk_segments}")
        return high_risk_segments

    def handle_threat_response(self, segment_hash: str):
        """
        Manages responses to a detected threat, initiating replication or rollback as appropriate.
        
        Args:
            segment_hash (str): Hash of the segment that failed integrity.
        """
        high_risk_segments = self.detect_high_risk_segments()

        if segment_hash in high_risk_segments:
            logger.warning(f"High-risk segment {segment_hash} detected; initiating adaptive replication.")
            adaptive_replication(segment_hash)
        elif len([t for t in self.threat_log if t["segment_hash"] == segment_hash]) >= self.replication_threshold:
            logger.info(f"Threshold for basic replication met for segment {segment_hash}. Initiating security replication.")
            self.trigger_security_replication(segment_hash)
        else:
            logger.info(f"Segment {segment_hash} remains under regular monitoring with no immediate replication action.")

    def trigger_security_replication(self, segment_hash: str):
        """
        Initiates standard security replication to reinforce segment availability.
        
        Args:
            segment_hash (str): Hash of the segment to replicate.
        """
        logger.info(f"Initiating security replication for segment {segment_hash}")
        trigger_security_replication(segment_hash)

    def rollback_segment(self, seigr_file: SeigrFile):
        """
        Rolls back a segment to its last verified secure state if threats are detected.
        
        Args:
            seigr_file (SeigrFile): Instance of SeigrFile representing the segment to roll back.
        """
        if not seigr_file.temporal_layers:
            logger.warning(f"No previous layers available for rollback on segment {seigr_file.hash}")
            return

        rollback_to_previous_state(seigr_file)
        logger.info(f"Successfully rolled back segment {seigr_file.hash} to a secure state.")

    def adaptive_monitoring(self, critical_threshold: int):
        """
        Executes an adaptive monitoring routine, handling threats that exceed critical thresholds.
        
        Args:
            critical_threshold (int): Threshold for immediately flagging segments as critical.
        """
        critical_segments = [
            seg for seg, count in self._get_threat_counts().items() if count >= critical_threshold
        ]

        for segment in critical_segments:
            logger.critical(f"Critical threat level reached for segment {segment}. Triggering urgent replication.")
            adaptive_replication(segment)

    def _get_threat_counts(self):
        """
        Internal method to count occurrences of threats per segment.
        
        Returns:
            dict: Mapping of segment hashes to the count of recorded threats.
        """
        threat_counts = {}
        for entry in self.threat_log:
            threat_counts[entry["segment_hash"]] = threat_counts.get(entry["segment_hash"], 0) + 1
        return threat_counts
