# src/replication/redistributor.py

import logging

logger = logging.getLogger(__name__)

def redistribute_replicas(replication_manager, segment_hash: str, target_replication: int) -> bool:
    """
    Attempts to redistribute or add replicas to meet the target replication count.

    Args:
        replication_manager: The ReplicationManager instance handling replication logic.
        segment_hash (str): Unique identifier for the segment.
        target_replication (int): Desired replication count for the segment.

    Returns:
        bool: True if replication was successfully adjusted, False otherwise.
    """
    current_hyphens = replication_manager.get_hyphens_with_replica(segment_hash)
    needed_replicas = target_replication - len(current_hyphens)

    if needed_replicas <= 0:
        logger.info(f"No additional replicas needed for segment {segment_hash}.")
        return True

    # Get additional hyphens that do not currently have the replica
    available_hyphens = [hyphen for hyphen in replication_manager.network_hyphens if hyphen not in current_hyphens]
    selected_hyphens = available_hyphens[:needed_replicas]

    success = True
    for hyphen in selected_hyphens:
        if not replication_manager._replicate_to_hyphen(segment_hash, hyphen):
            success = False
            logger.error(f"Failed to replicate segment {segment_hash} to hyphen {hyphen}")
        else:
            logger.info(f"Replicated segment {segment_hash} to hyphen {hyphen}")

    return success
