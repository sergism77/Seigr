import logging
from datetime import datetime, timezone
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata
from src.crypto.hash_utils import hypha_hash
from src.dot_seigr.replication_manager import ReplicationManager

logger = logging.getLogger(__name__)

replication_manager = ReplicationManager(network_nodes=["node1", "node2", "node3"])  # Example nodes

def check_replication_count(current_count: int, min_replication: int, network_replication: int, access_count: int) -> int:
    """
    Checks and adjusts the replication count based on minimum requirements, network status, and demand.

    Args:
        current_count (int): Current replication count of the segment.
        min_replication (int): Minimum replication threshold.
        network_replication (int): Current replication level across the network.
        access_count (int): Access count, used to adjust replication based on demand.

    Returns:
        int: Updated replication count.
    """
    # Ensure minimum replication threshold
    if network_replication < min_replication:
        updated_count = max(current_count, min_replication)
        logger.info(f"Replication count for segment updated to {updated_count} to meet minimum replication.")
    else:
        # Scale replication dynamically based on demand
        demand_scale_factor = calculate_demand_scale(access_count)
        updated_count = max(current_count, demand_scale_factor)
        logger.info(f"Replication count dynamically adjusted based on access demand to {updated_count} (access count: {access_count}).")

    return updated_count

def calculate_demand_scale(access_count: int) -> int:
    """
    Calculates a scaling factor for replication based on segment access frequency.

    Args:
        access_count (int): Number of times the segment has been accessed.

    Returns:
        int: Scaling factor for replication based on demand.
    """
    if access_count > 1000:
        return 12  # High-demand threshold, aggressive replication
    elif access_count > 500:
        return 8   # Moderate to high demand
    elif access_count > 100:
        return 5   # Moderate demand
    elif access_count > 10:
        return 3   # Low demand
    return 1       # Minimal demand

def adaptive_replication(segment: SegmentMetadata, threat_level: int, current_count: int, min_replication: int):
    """
    Adjusts replication count adaptively based on the threat level for high-risk segments.

    Args:
        segment (SegmentMetadata): Protobuf segment metadata to replicate.
        threat_level (int): Threat level indicating urgency for replication.
        current_count (int): Current replication count.
        min_replication (int): Minimum replication threshold.
    """
    segment_hash = segment.segment_hash

    # Calculate replication needs based on threat level
    if threat_level >= 5:
        required_replication = current_count + 5  # Critical threat response
    elif threat_level >= 3:
        required_replication = current_count + 3  # High-risk scaling
    elif threat_level >= 1:
        required_replication = current_count + 2  # Moderate threat
    else:
        required_replication = max(min_replication, current_count + 1)  # Low-risk adjustment

    logger.info(f"Adaptive replication initiated for segment {segment_hash} at threat level {threat_level}. "
                f"Updating replication count to {required_replication}.")
    replicate_segment(segment_hash, required_replication - current_count)

def self_heal_replication(segment: SegmentMetadata, current_replication: int, min_replication: int, network_status: dict) -> bool:
    """
    Initiates self-healing for segments with replication below the required threshold.

    Args:
        segment (SegmentMetadata): Protobuf segment metadata to check.
        current_replication (int): Current replication count for the segment.
        min_replication (int): Minimum replication threshold.
        network_status (dict): Current replication status across network nodes.

    Returns:
        bool: True if self-healing was initiated, False otherwise.
    """
    segment_hash = segment.segment_hash
    current_network_replication = network_status.get(segment_hash, 0)

    if current_network_replication < min_replication:
        replication_needed = min_replication - current_network_replication
        replicate_segment(segment_hash, replication_needed)
        logger.info(f"Self-healing triggered for segment {segment_hash}. Replicating {replication_needed} additional copies.")
        return True
    else:
        logger.info(f"Segment {segment_hash} meets minimum replication requirements (current: {current_network_replication}).")
        return False

def replicate_segment(segment_hash: str, replication_needed: int):
    """
    Distributes additional replicas of the segment to meet updated replication needs.

    Args:
        segment_hash (str): Hash of the segment to replicate.
        replication_needed (int): Number of additional replicas needed.
    """
    if replication_needed > 0:
        success = replication_manager.replicate_segment_to_nodes(segment_hash, replication_needed)
        if success:
            logger.info(f"Successfully replicated segment {segment_hash} to {replication_needed} additional nodes.")
        else:
            logger.error(f"Failed to replicate segment {segment_hash} to required nodes.")
    else:
        logger.info(f"No additional replication needed for segment {segment_hash}. Current replication is sufficient.")

def monitor_and_adapt_replication(segments_status: dict, min_replication: int, demand_threshold: int):
    """
    Monitors and dynamically adapts replication based on demand and network conditions.

    Args:
        segments_status (dict): Status info for each segment, including access counts and current replication.
        min_replication (int): Minimum replication requirement.
        demand_threshold (int): Access threshold to identify high-demand segments.
    """
    for segment_hash, status in segments_status.items():
        access_count = status.get("access_count", 0)
        current_replication = status.get("current_replication", 1)

        # Adapt replication based on demand if access exceeds threshold
        if access_count > demand_threshold:
            logger.info(f"High demand detected for segment {segment_hash}. Access count: {access_count}")
            replication_count = check_replication_count(
                current_replication, min_replication, status.get("network_replication", 1), access_count
            )
            replicate_segment(segment_hash, replication_count - current_replication)
        else:
            logger.debug(f"Segment {segment_hash} access below threshold. No adaptive replication needed.")
