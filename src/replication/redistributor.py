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
    current_nodes = replication_manager.get_nodes_with_replica(segment_hash)
    needed_replicas = target_replication - len(current_nodes)

    if needed_replicas <= 0:
        logger.info(f"No additional replicas needed for segment {segment_hash}.")
        return True

    # Get additional nodes that do not currently have the replica
    available_nodes = [node for node in replication_manager.network_nodes if node not in current_nodes]
    selected_nodes = available_nodes[:needed_replicas]

    success = True
    for node in selected_nodes:
        if not replication_manager._replicate_to_node(segment_hash, node):
            success = False
            logger.error(f"Failed to replicate segment {segment_hash} to node {node}")
        else:
            logger.info(f"Replicated segment {segment_hash} to node {node}")

    return success
