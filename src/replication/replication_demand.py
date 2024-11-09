# src/replication/replication_demand.py
import logging
from src.replication.replication_manager import ReplicationManager
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata

logger = logging.getLogger(__name__)

class DemandBasedReplication:
    def __init__(self, replication_manager: ReplicationManager):
        """
        Initializes DemandBasedReplication to handle replication based on access demand.
        
        Args:
            replication_manager (ReplicationManager): Manager to handle replication requests.
        """
        if not isinstance(replication_manager, ReplicationManager):
            raise ValueError("Expected an instance of ReplicationManager")
        
        self.replication_manager = replication_manager

    def adapt_based_on_demand(self, segment: SegmentMetadata, access_count: int, demand_threshold: int, min_replication: int) -> bool:
        """
        Adjusts replication based on segment's access demand.
        
        Args:
            segment (SegmentMetadata): Metadata of the segment to replicate.
            access_count (int): Access count of the segment.
            demand_threshold (int): Access threshold for high demand.
            min_replication (int): Minimum replication level.
        
        Returns:
            bool: True if replication was triggered, False otherwise.
        """
        if access_count < demand_threshold:
            logger.info(f"Segment {segment.segment_hash} access below threshold ({access_count}/{demand_threshold}). No replication needed.")
            return False
        
        new_replication_count = self.calculate_demand_scale(access_count, min_replication)
        logger.info(f"Demand-based replication adjustment for segment {segment.segment_hash}. "
                    f"New replication count: {new_replication_count}")
        
        try:
            success = self.replication_manager.replicate_segment(segment.segment_hash, new_replication_count)
            if success:
                logger.info(f"Demand-based replication completed for segment {segment.segment_hash} with replication count: {new_replication_count}")
                return True
            else:
                raise ValueError(f"Replication failed for segment {segment.segment_hash}. Requested count: {new_replication_count}")
        
        except Exception as e:
            logger.error(f"Error during demand-based replication for segment {segment.segment_hash}: {e}")
            raise ValueError(f"Replication failed for segment {segment.segment_hash}") from e

    def calculate_demand_scale(self, access_count: int, min_replication: int) -> int:
        """
        Calculates the required replication count based on access demand.
        
        Args:
            access_count (int): Number of times the segment has been accessed.
            min_replication (int): Minimum replication threshold.
        
        Returns:
            int: Scaled replication count based on demand.
        """
        if access_count > 1000:
            replication_count = max(min_replication, 12)  # High demand: aggressive replication
        elif access_count > 500:
            replication_count = max(min_replication, 8)   # Moderate to high demand
        elif access_count > 100:
            replication_count = max(min_replication, 5)   # Moderate demand
        elif access_count > 10:
            replication_count = max(min_replication, 3)   # Low demand
        else:
            replication_count = min_replication           # Minimal demand
        
        logger.debug(f"Calculated demand-based replication count for access {access_count}: {replication_count}")
        return replication_count

    def monitor_and_replicate_by_demand(self, segments_status: dict, demand_threshold: int, min_replication: int):
        """
        Monitors access counts and adapts replication for each segment exceeding demand threshold.
        
        Args:
            segments_status (dict): Status info for each segment, including access counts and current replication.
            demand_threshold (int): Access threshold to trigger high-demand replication.
            min_replication (int): Minimum replication level required for all segments.
        """
        for segment_hash, status in segments_status.items():
                access_count = status.get("access_count", 0)
                segment_metadata = status.get("segment_metadata")
                
                if not segment_metadata:
                    logger.warning(f"Missing metadata for segment {segment_hash}. Skipping demand-based replication check.")
                    continue

                if access_count >= demand_threshold:
                    try:
                        self.adapt_based_on_demand(segment_metadata, access_count, demand_threshold, min_replication)
                    except Exception as e:
                        logger.error(f"Demand-based replication failed for segment {segment_hash}: {e}")

    def manage_replication_demand(self, segments_status: dict, demand_threshold: int = 10, min_replication: int = 3):
        """
        Entry function to monitor demand and manage replication scaling as needed.
        
        Args:
            segments_status (dict): Dictionary of segment statuses including metadata and access counts.
            demand_threshold (int): Minimum access count to trigger demand-based replication.
            min_replication (int): Minimum replication level for scaling purposes.
        """
        logger.info("Starting demand-based replication management across segments.")
        
        # Call monitor_and_replicate_by_demand with the provided parameters
        self.monitor_and_replicate_by_demand(segments_status, demand_threshold, min_replication)
        
        logger.info("Demand-based replication management completed.")
