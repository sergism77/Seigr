# src/dot_seigr/replication.py
import logging

logger = logging.getLogger(__name__)

def check_replication_count(current_count: int, min_replication: int, network_replication: int) -> int:
    """Checks replication requirements and updates count if needed."""
    if network_replication < min_replication:
        updated_count = max(current_count, network_replication)
        logger.info(f"Replication count updated to {updated_count}.")
        return updated_count
    logger.info(f"Replication count ({network_replication}) meets or exceeds minimum ({min_replication}).")
    return current_count
