import logging

from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata
from src.replication.replication_manager import ReplicationManager

logger = logging.getLogger(__name__)


def initiate_self_heal(self, segment_hash: str, target_replication: int) -> bool:
    """
    Initiates a self-healing process for a segment to ensure it meets target replication levels.

    Args:
        segment_hash (str): The hash of the segment needing self-healing.
        target_replication (int): Desired replication count to achieve during self-heal.

    Returns:
        bool: True if self-healing was successful, False otherwise.
    """
    logger.info(
        f"Initiating self-heal process for segment {segment_hash} with target replication: {target_replication}"
    )

    current_hyphens = self.replication_manager.get_hyphens_with_replica(segment_hash)
    current_replication_count = len(current_hyphens)

    if current_replication_count >= target_replication:
        logger.info(
            f"Segment {segment_hash} already meets the target replication count ({current_replication_count}/{target_replication}). No self-healing required."
        )
        return True

    additional_replicas_needed = target_replication - current_replication_count
    logger.info(
        f"Additional replicas needed for segment {segment_hash}: {additional_replicas_needed}"
    )

    success = self.replication_manager.redistribute_replicas(segment_hash, target_replication)
    if success:
        logger.info(
            f"Self-healing successful for segment {segment_hash}, reaching target replication: {target_replication}"
        )
        return True
    else:
        logger.error(
            f"Self-healing failed for segment {segment_hash}. Could not reach target replication: {target_replication}"
        )
        return False


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

    def check_and_self_heal(
        self,
        segment: SegmentMetadata,
        current_replication: int,
        network_replication: int,
        min_replication: int,
    ) -> bool:
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
            logger.info(
                f"Segment {segment.segment_hash} meets minimum replication requirements ({network_replication}/{min_replication}). No self-healing needed."
            )
            return False

        replication_needed = min_replication - network_replication
        logger.info(
            f"Self-healing triggered for segment {segment.segment_hash}. "
            f"Current replication: {network_replication}, Required: {min_replication}. "
            f"Replicating {replication_needed} additional copies."
        )

        # Trigger replication
        try:
            success = self.replication_manager.replicate_segment(
                segment.segment_hash, replication_needed
            )
            if success:
                logger.info(
                    f"Self-healing replication completed for segment {segment.segment_hash}. "
                    f"Total replication count is now {min_replication}."
                )
                return True
            else:
                raise ValueError(
                    f"Replication failed for segment {segment.segment_hash}. Requested {replication_needed} replicas."
                )

        except Exception as e:
            logger.error(
                f"Error during self-healing replication for segment {segment.segment_hash}: {e}"
            )
            raise ValueError(
                f"Replication failed for segment {segment.segment_hash}"
            ) from e  # Wrap in ValueError

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
                logger.warning(
                    f"Missing metadata for segment {segment_hash}. Skipping self-heal check."
                )
                continue

            # Only call check_and_self_heal if network_replication is below min_replication
            if network_replication < min_replication:
                try:
                    self.check_and_self_heal(
                        segment,
                        current_replication,
                        network_replication,
                        min_replication,
                    )
                except Exception as e:
                    logger.error(f"Failed self-healing for segment {segment_hash}: {e}")

    def initiate_self_heal(
        segment_hash: str,
        replication_manager: ReplicationManager,
        target_replication: int,
    ) -> bool:
        """
        Initiates a self-healing process for a segment to ensure it meets target replication levels.

        Args:
            segment_hash (str): The hash of the segment needing self-healing.
            replication_manager (ReplicationManager): Manager to handle replication operations.
            target_replication (int): Desired replication count to achieve during self-heal.

        Returns:
            bool: True if self-healing was successful, False otherwise.
        """
        logger.info(
            f"Initiating self-heal process for segment {segment_hash} with target replication: {target_replication}"
        )

        # Get the current hyphens holding replicas of the segment
        current_hyphens = replication_manager.get_hyphens_with_replica(segment_hash)
        current_replication_count = len(current_hyphens)

        # Check if the segment already meets the desired replication count
        if current_replication_count >= target_replication:
            logger.info(
                f"Segment {segment_hash} already meets the target replication count ({current_replication_count}/{target_replication}). No self-healing required."
            )
            return True

        # Calculate additional replicas needed to meet the target
        additional_replicas_needed = target_replication - current_replication_count
        logger.info(
            f"Additional replicas needed for segment {segment_hash}: {additional_replicas_needed}"
        )

        # Attempt to replicate to meet the target replication count
        success = replication_manager.redistribute_replicas(segment_hash, target_replication)
        if success:
            logger.info(
                f"Self-healing successful for segment {segment_hash}, reaching target replication: {target_replication}"
            )
            return True
        else:
            logger.error(
                f"Self-healing failed for segment {segment_hash}. Could not reach target replication: {target_replication}"
            )
            return False
