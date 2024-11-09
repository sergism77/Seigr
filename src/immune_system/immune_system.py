# src/immune_system/immune_system.py

import logging
from datetime import datetime, timezone
from src.immune_system.integrity_monitoring import immune_ping
from src.replication.replication_controller import ReplicationController
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata
from src.dot_seigr.seigr_file import SeigrFile
from src.immune_system.threat_detection import ThreatDetector
from src.immune_system.adaptive_monitoring import AdaptiveMonitor
from src.immune_system.rollback_handling import rollback_segment

logger = logging.getLogger(__name__)

class ImmuneSystem:
    def __init__(self, monitored_segments, replication_controller: ReplicationController, critical_threshold: int = 10):
        """
        Initializes the Immune System to monitor segments, manage adaptive replication, and handle threats.

        Args:
            monitored_segments (dict): A dictionary of segments to monitor.
            replication_controller (ReplicationController): The controller handling replication requests.
            critical_threshold (int): The threat level threshold to trigger critical replication.
        """
        self.monitored_segments = monitored_segments
        self.replication_controller = replication_controller
        self.threat_detector = ThreatDetector(replication_controller)
        self.adaptive_monitor = AdaptiveMonitor(replication_controller, self.threat_detector, critical_threshold)

    def rollback_segment(self, seigr_file: SeigrFile) -> bool:
        """
        Wrapper for the rollback function from rollback_handling, to use in ImmuneSystem.

        Args:
            seigr_file (SeigrFile): The segment file to attempt to roll back.

        Returns:
            bool: True if the rollback was successful, False otherwise.
        """
        result = rollback_segment(seigr_file)
        if result:
            logger.info(f"Rollback succeeded for segment {seigr_file.hash}.")
        else:
            logger.warning(f"Rollback failed for segment {seigr_file.hash}.")
        return result
    
    def immune_ping(self, segment_metadata: SegmentMetadata, data: bytes) -> bool:
        """
        Sends an integrity ping to check the segment's integrity and manages replication if needed.

        Args:
            segment_metadata (SegmentMetadata): Metadata of the segment to verify.
            data (bytes): Data of the segment to verify integrity.

        Returns:
            bool: True if the integrity check passed, False if it failed.
        """
        segment_hash = segment_metadata.segment_hash
        logger.debug(f"Starting immune_ping on segment {segment_hash}.")

        # Perform the integrity check
        is_valid = immune_ping(segment_metadata, data)

        # If the check fails, trigger adaptive monitoring without logging the threat here
        if not is_valid:
            logger.warning(f"Integrity check failed for segment {segment_hash}.")
            
            # Trigger adaptive monitoring, which will handle threat logging
            self.adaptive_monitor.monitor_segment(segment_metadata, data)  

        return is_valid

    def monitor_integrity(self):
        """
        Continuously monitors the integrity of all segments in `monitored_segments`.
        """
        for segment_metadata in self.monitored_segments.values():
            data = b""  # Placeholder; in practice, retrieve actual data
            self.immune_ping(segment_metadata, data)

    def handle_threat_response(self, segment_hash: str):
        """
        Responds to a detected threat by adjusting replication based on threat level.
        
        Args:
            segment_hash (str): The hash of the segment facing the threat.
        """
        from src.replication.replication_self_heal import initiate_self_heal  # Delayed import to avoid circular dependencies
        logger.info(f"Handling threat response for segment {segment_hash}.")
        self.adaptive_monitor._handle_adaptive_replication(segment_hash)

    def run_adaptive_monitoring_cycle(self):
        """
        Executes a complete adaptive monitoring cycle for all segments.
        """
        segments_status = {
            segment_hash: {"segment_metadata": metadata, "data": b""}  # Placeholder for real data
            for segment_hash, metadata in self.monitored_segments.items()
        }
        self.adaptive_monitor.run_monitoring_cycle(segments_status)

    def escalate_critical_segments(self):
        """
        Escalates replication for all segments reaching the critical threat level.
        """
        logger.info("Escalating critical segments.")
        self.adaptive_monitor.escalate_critical_segments()
