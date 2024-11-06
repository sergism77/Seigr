import logging
from src.dot_seigr.replication_manager import ReplicationManager
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata

logger = logging.getLogger(__name__)

class SelfHealReplication:
    def __init__(self, replication_manager: ReplicationManager):
        """
        Initializes SelfHealReplication to manage self-healing for segment replication.
        
        Args:
            replication_manager (ReplicationManager): Manager to handle actual replication requests.
        """
        if not isinstance(replication_manager, ReplicationManager):
            raise ValueError("Expected an instance of ReplicationManager")
        
        self.replication_manager = replication_manager

    def check_and_self_heal(self, segment: SegmentMetadata, current_replication: int, network_replication: int, min_replication: int) -> bool:
        """
        Checks if self-healing is needed and triggers replication to reach the minimum threshold.
        
        Args:
            segment (SegmentMetadata): Metadata of the segment to check.
            current_replication (int): Current replication count of the segment.
            network_replication (int): Total replication across the network.
            min_replication (int): Minimum replication threshold.
        
        Returns:
            bool: True if self-healing replication was triggered, False otherwise.
        
        Raises:
            ValueError: If replication request cannot be fulfilled.
        """
        if network_replication >= min_replication:
            logger.info(f"Segment {segment.segment_hash} meets minimum replication requirements ({network_replication}/{min_replication}). No self-healing needed.")
            return False
        
        replication_needed = min_replication - network_replication
        logger.info(f"Self-healing triggered for segment {segment.segment_hash}. "
                    f"Current replication: {network_replication}, Required: {min_replication}. "
                    f"Replicating {replication_needed} additional copies.")
        
        # Trigger replication
        try:
            success = self.replication_manager.replicate_segment(segment.segment_hash, replication_needed)
            if success:
                logger.info(f"Self-healing replication completed for segment {segment.segment_hash}. "
                            f"Total replication count is now {min_replication}.")
                return True
            else:
                raise ValueError(f"Replication failed for segment {segment.segment_hash}. Requested {replication_needed} replicas.")
        
        except Exception as e:
            logger.error(f"Error during self-healing replication for segment {segment.segment_hash}: {e}")
            raise

    def monitor_and_self_heal(self, segments_status: dict, min_replication: int):
        """
        Monitors network replication for each segment and applies self-healing as necessary.
        
        Args:
            segments_status (dict): Dictionary with segment hash as key and replication details as value.
            min_replication (int): Minimum replication level for all segments.
        """
        for segment_hash, status in segments_status.items():
            current_replication = status.get("current_replication", 0)
            network_replication = status.get("network_replication", 0)
            segment = status.get("segment_metadata")

            if not segment:
                logger.warning(f"Missing metadata for segment {segment_hash}. Skipping self-heal check.")
                continue

            # Trigger self-healing if needed
            try:
                self.check_and_self_heal(segment, current_replication, network_replication, min_replication)
            except Exception as e:
                logger.error(f"Failed self-healing for segment {segment_hash}: {e}")
