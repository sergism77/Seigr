import logging
from datetime import datetime
from .integrity import verify_segment_integrity
from .replication import trigger_security_replication, adaptive_replication
from .seigr_file import SeigrFile
from .rollback import rollback_to_previous_state

logger = logging.getLogger(__name__)

class ImmuneSystem:
    def __init__(self, monitored_segments, replication_threshold=3, adaptive_threshold=5):
        """
        Initializes the immune system with monitored segments and adaptive thresholds.
        
        Args:
            monitored_segments (dict): Dictionary of segment hashes and their associated data.
            replication_threshold (int): Number of threat detections before basic replication is triggered.
            adaptive_threshold (int): Number of detections before high-risk adaptive replication is triggered.
        """
        self.monitored_segments = monitored_segments  # e.g., {hash: segment_data}
        self.threat_log = []
        self.replication_threshold = replication_threshold
        self.adaptive_threshold = adaptive_threshold

    def immune_ping(self, segment_hash: str) -> bool:
        """
        Sends an integrity ping, using multi-dimensional hashes, to check integrity of a specific segment.
        
        Args:
            segment_hash (str): Hash of the segment to check.
        
        Returns:
            bool: True if integrity check passed, False if failed.
        """
        segment_data = self.monitored_segments.get(segment_hash)
        if not segment_data:
            logger.error(f"Segment {segment_hash} not found in monitored segments.")
            return False

        # Perform multi-dimensional hash verification
        valid = verify_segment_integrity(segment_hash, segment_data)
        if not valid:
            self.record_threat(segment_hash)
            self.handle_threat_response(segment_hash)
        return valid

    def monitor_integrity(self):
        """
        Continuously monitors integrity of all segments in monitored_segments.
        """
        for segment_hash in self.monitored_segments.keys():
            self.immune_ping(segment_hash)

    def record_threat(self, segment_hash: str):
        """
        Records a threat instance for a segment and logs the event.
        
        Args:
            segment_hash (str): Hash of the segment that failed integrity.
        """
        threat_entry = {
            "segment_hash": segment_hash,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.threat_log.append(threat_entry)
        logger.info(f"Threat recorded for segment {segment_hash}")

    def detect_high_risk_segments(self):
        """
        Analyzes threat logs for repeated integrity failures.
        
        Returns:
            list: Segments flagged for high-risk replication or rollback.
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
        Handles response to a detected threat, triggering replication or rollback as needed.
        
        Args:
            segment_hash (str): Hash of the segment that failed integrity.
        """
        high_risk_segments = self.detect_high_risk_segments()
        
        if segment_hash in high_risk_segments:
            logger.warning(f"Segment {segment_hash} identified as high-risk; triggering adaptive replication.")
            adaptive_replication(segment_hash)
        elif len(self.threat_log) >= self.replication_threshold:
            logger.warning(f"Replication threshold met; initiating standard security replication for segment {segment_hash}.")
            self.trigger_security_replication(segment_hash)
        else:
            logger.info(f"Segment {segment_hash} remains under regular monitoring.")

    def trigger_security_replication(self, segment_hash: str):
        """
        Initiates security replication to reinforce a segment's presence in response to a detected threat.
        
        Args:
            segment_hash (str): Hash of the segment to replicate.
        """
        logger.warning(f"Triggering security replication for segment {segment_hash}")
        trigger_security_replication(segment_hash)

    def rollback_segment(self, seigr_file: SeigrFile):
        """
        Rolls back a segment to a previous secure state.
        
        Args:
            seigr_file (SeigrFile): Instance of SeigrFile to roll back.
        """
        if not seigr_file.temporal_layers:
            logger.warning(f"No previous layers to roll back for segment {seigr_file.hash}")
            return

        rollback_to_previous_state(seigr_file)
        logger.info(f"Rolled back segment {seigr_file.hash} to a previous secure state.")
