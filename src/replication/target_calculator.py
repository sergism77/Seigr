# src/replication/target_calculator.py

import logging

logger = logging.getLogger(__name__)


def calculate_target_replication(demand_level: int, threat_level: int) -> int:
    """
    Calculates the target replication count based on demand and threat levels.

    Args:
        demand_level (int): Current demand level for the segment.
        threat_level (int): Current threat level for the segment.

    Returns:
        int: Calculated target replication count.
    """
    base_replication = 3  # Base replication count

    # Adjust replication based on demand and threat levels
    if demand_level > 5:
        base_replication += 2
    elif demand_level > 8:
        base_replication += 4

    if threat_level > 7:
        base_replication += 3
    elif threat_level > 9:
        base_replication += 5

    logger.debug(
        f"Calculated target replication: {base_replication} (demand: {demand_level}, threat: {threat_level})"
    )
    return base_replication
