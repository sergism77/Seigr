import logging

from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata
from src.replication.replication_manager import ReplicationManager

logger = logging.getLogger(__name__)


def detect_replication_threat(
    segment_hash: str,
    replication_manager: ReplicationManager,
    error_rate: float,
    access_frequency: int,
    threshold_error_rate: float = 0.05,
    high_demand_threshold: int = 500,
) -> bool:
    """
    Analyzes a segment for replication threats based on error rate and access frequency.

    Args:
        segment_hash (str): Hash of the segment to analyze.
        replication_manager (ReplicationManager): Manager to assist with replication decisions.
        error_rate (float): Rate of errors detected for the segment.
        access_frequency (int): Frequency of access for the segment.
        threshold_error_rate (float): Error rate threshold to trigger a replication threat.
        high_demand_threshold (int): Access threshold to trigger high-demand replication.

    Returns:
        bool: True if a replication threat is detected, False otherwise.
    """
    logger.info(f"Analyzing replication threat for segment {segment_hash}.")

    # Check if error rate exceeds threshold
    if error_rate > threshold_error_rate:
        logger.warning(
            f"High error rate detected for segment {segment_hash} (Error Rate: {error_rate}). Threat detected."
        )
        return True

    # Check if access frequency indicates high demand
    if access_frequency > high_demand_threshold:
        logger.info(
            f"High demand detected for segment {segment_hash} (Access Frequency: {access_frequency}). Triggering replication."
        )
        replication_manager.replicate_segment(
            segment_hash, access_frequency // high_demand_threshold
        )
        return True

    logger.debug(f"No replication threat detected for segment {segment_hash}.")
    return False


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

    def adaptive_threat_replication(
        self, segment: SegmentMetadata, threat_level: int, min_replication: int
    ):
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
            logger.info(
                f"Adaptive replication adjustment for segment {segment.segment_hash}. "
                f"Replication needed: {replication_needed}"
            )

            # Trigger replication
            success = self.replication_manager.replicate_segment(
                segment.segment_hash, replication_needed
            )
            if success:
                logger.info(
                    f"Replication successfully completed for segment {segment.segment_hash} "
                    f"with replication count: {replication_needed}"
                )
            else:
                raise ValueError(
                    f"Replication failed for segment {segment.segment_hash}. "
                    f"Requested: {replication_needed}"
                )
        except Exception as e:
            logger.error(
                f"Error during threat-based replication for segment {segment.segment_hash}: {e}"
            )
            raise ValueError(
                f"Replication failed for segment {segment.segment_hash}"
            ) from e  # Wrap in ValueError

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

        logger.debug(
            f"Calculated replication count for threat level {threat_level}: {replication_count}"
        )
        return replication_count

    def handle_high_risk_segments(self, high_risk_segments: list, min_replication: int):
        """
        Initiates adaptive replication for a list of high-risk segments.

        Args:
            high_risk_segments (list): List of high-risk SegmentMetadata instances.
            min_replication (int): Minimum replication level required.
        """
        for segment in high_risk_segments:
            logger.warning(
                f"High-risk segment detected: {segment.segment_hash}. Initiating adaptive replication."
            )
            self.adaptive_threat_replication(
                segment, threat_level=5, min_replication=min_replication
            )
