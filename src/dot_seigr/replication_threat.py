import logging
from src.dot_seigr.replication_manager import ReplicationManager
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata

logger = logging.getLogger(__name__)

class ThreatBasedReplication:
    def __init__(self, replication_manager: ReplicationManager):
        """
        Initializes ThreatBasedReplication for handling replication based on segment threat level.
        
        Args:
            replication_manager (ReplicationManager): Manager to execute replication requests.
        """
        if not isinstance(replication_manager, ReplicationManager):
            raise ValueError("Expected an instance of ReplicationManager")
        
        self.replication_manager = replication_manager

    def adaptive_threat_replication(self, segment: SegmentMetadata, threat_level: int, min_replication: int):
        """
        Adjusts replication based on the given threat level.
        
        Args:
            segment (SegmentMetadata): Metadata of the segment to replicate.
            threat_level (int): Threat level indicating urgency for replication.
            min_replication (int): Minimum replication level.
        
        Raises:
            ValueError: If replication requirements could not be met.
        """
        try:
            replication_needed = self.calculate_threat_replication(threat_level, min_replication)
            logger.info(f"Adaptive replication adjustment for segment {segment.segment_hash}. "
                        f"Replication needed: {replication_needed}")
            
            # Trigger replication
            success = self.replication_manager.replicate_segment(segment.segment_hash, replication_needed)
            if success:
                logger.info(f"Replication successfully completed for segment {segment.segment_hash} "
                            f"with replication count: {replication_needed}")
            else:
                raise ValueError(f"Replication failed for segment {segment.segment_hash}. "
                                f"Requested: {replication_needed}")
        except Exception as e:
            logger.error(f"Error during threat-based replication for segment {segment.segment_hash}: {e}")
            raise ValueError(f"Replication failed for segment {segment.segment_hash}") from e  # Wrap in ValueError

    def calculate_threat_replication(self, threat_level: int, min_replication: int) -> int:
        """
        Calculates replication needs based on threat level.
        
        Args:
            threat_level (int): Threat level of the segment.
            min_replication (int): Minimum replication threshold.
        
        Returns:
            int: Calculated replication count based on threat level.
        """
        # Define replication scaling based on threat level
        if threat_level >= 5:
            replication_count = min_replication + 5
        elif threat_level >= 3:
            replication_count = min_replication + 3
        elif threat_level >= 1:
            replication_count = min_replication + 2
        else:
            replication_count = min_replication
        
        logger.debug(f"Calculated replication count for threat level {threat_level}: {replication_count}")
        return replication_count

    def handle_high_risk_segments(self, high_risk_segments: list, min_replication: int):
        """
        Initiates adaptive replication for a list of high-risk segments.
        
        Args:
            high_risk_segments (list): List of high-risk SegmentMetadata instances.
            min_replication (int): Minimum replication level required.
        """
        for segment in high_risk_segments:
            logger.warning(f"High-risk segment detected: {segment.segment_hash}. Initiating adaptive replication.")
            self.adaptive_threat_replication(segment, threat_level=5, min_replication=min_replication)
