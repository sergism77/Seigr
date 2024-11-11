import logging
from src.replication.replication_manager import ReplicationManager
from .replication_demand import DemandBasedReplication
from .replication_threat import ThreatBasedReplication
from .replication_self_heal import SelfHealReplication
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata

logger = logging.getLogger(__name__)

class ReplicationController:
    def __init__(self, min_replication: int, demand_threshold: int, network_hyphens: list):
        """
        Initializes the ReplicationController to manage all replication strategies.
        
        Args:
            min_replication (int): Minimum replication level required across all segments.
            demand_threshold (int): Access count threshold to trigger high-demand replication.
            network_hyphens (list): List of network hyphens available for replication.
        """
        if not network_hyphens:
            raise ValueError("ReplicationController requires a non-empty list of network hyphens.")
        
        self.min_replication = min_replication
        self.demand_threshold = demand_threshold
        self.replication_manager = ReplicationManager(network_hyphens)
        self.demand_replicator = DemandBasedReplication(self.replication_manager)
        self.threat_replicator = ThreatBasedReplication(self.replication_manager)
        self.self_heal_replicator = SelfHealReplication(self.replication_manager)
        
        logger.info("ReplicationController initialized with min_replication=%d, demand_threshold=%d, hyphens=%s",
                    min_replication, demand_threshold, network_hyphens)

    def monitor_and_adapt_replication(self, segments_status: dict):
        """
        Monitors replication status and dynamically adapts replication based on demand, threat, and self-healing needs.
        
        Args:
            segments_status (dict): Status info for each segment, including access counts, threat levels, and replication details.
        """
        for segment_hash, status in segments_status.items():
            segment_metadata = status.get("segment_metadata")
            if not isinstance(segment_metadata, SegmentMetadata):
                logger.warning(f"Skipping replication adaptation for segment {segment_hash}: Invalid or missing metadata.")
                continue
            
            access_count = status.get("access_count", 0)
            threat_level = status.get("threat_level", 0)
            current_replication = status.get("current_replication", 1)
            network_replication = status.get("network_replication", 1)

            logger.debug(f"Monitoring segment {segment_hash}: Access={access_count}, Threat={threat_level}, "
                         f"Current Replication={current_replication}, Network Replication={network_replication}")

            # Trigger demand-based replication if access exceeds threshold
            self._handle_demand_replication(segment_metadata, access_count)
            
            # Trigger threat-based replication according to threat level
            self._handle_threat_replication(segment_metadata, threat_level)
            
            # Perform self-healing replication if below minimum replication
            self._handle_self_healing(segment_metadata, current_replication, network_replication)

    def _handle_demand_replication(self, segment_metadata: SegmentMetadata, access_count: int):
        """
        Manages replication based on access demand if access count exceeds the demand threshold.
        
        Args:
            segment_metadata (SegmentMetadata): Metadata of the segment to replicate.
            access_count (int): Number of times the segment has been accessed.
        """
        if access_count > self.demand_threshold:
            logger.info(f"High demand detected for segment {segment_metadata.segment_hash} with access count {access_count}.")
            try:
                self.demand_replicator.adapt_based_on_demand(
                    segment_metadata,
                    access_count,
                    self.demand_threshold,
                    self.min_replication
                )
            except Exception as e:
                logger.error(f"Demand replication failed for segment {segment_metadata.segment_hash}: {e}")

    def _handle_threat_replication(self, segment_metadata: SegmentMetadata, threat_level: int):
        """
        Manages replication based on threat level for segments at risk.
        
        Args:
            segment_metadata (SegmentMetadata): Metadata of the segment to replicate.
            threat_level (int): Threat level indicating urgency for replication.
        """
        if threat_level > 0:
            logger.info(f"Threat-based replication triggered for segment {segment_metadata.segment_hash} with threat level {threat_level}.")
            try:
                self.threat_replicator.adaptive_threat_replication(
                    segment_metadata,
                    threat_level,
                    self.min_replication
                )
            except Exception as e:
                logger.error(f"Threat replication failed for segment {segment_metadata.segment_hash}: {e}")

    def _handle_self_healing(self, segment_metadata: SegmentMetadata, current_replication: int, network_replication: int):
        """
        Ensures minimum replication through self-healing if replication is below threshold.
        
        Args:
            segment_metadata (SegmentMetadata): Metadata of the segment to replicate.
            current_replication (int): Current number of replicas for the segment.
            network_replication (int): Current replication level across the network.
        """
        if network_replication < self.min_replication:
            logger.info(f"Self-healing required for segment {segment_metadata.segment_hash}. Current replication is below minimum.")
            try:
                self.self_heal_replicator.check_and_self_heal(
                    segment_metadata,
                    current_replication,
                    network_replication,
                    self.min_replication
                )
            except Exception as e:
                logger.error(f"Self-healing replication failed for segment {segment_metadata.segment_hash}: {e}")
