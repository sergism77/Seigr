import logging
import os
from datetime import datetime, timezone

from src.crypto.hypha_crypt import hypha_hash
from src.replication.replication_controller import ReplicationController
from src.replication.replication_threat import ThreatBasedReplication
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import SeedDotSeigr

logger = logging.getLogger(__name__)


class SeigrClusterManager:
    """
    Manages segment clustering, replication, and metadata for Seigr files.
    """

    def __init__(
        self,
        creator_id: str,
        original_filename: str = None,
        original_extension: str = None,
        version: str = "1.0",
    ):
        """
        Initializes the SeigrClusterManager with metadata and replication controller.

        Args:
            creator_id (str): Unique identifier for the creator of the file.
            original_filename (str, optional): Original filename for metadata reference.
            original_extension (str, optional): Original file extension for metadata.
            version (str): Cluster format version.
        """
        self.creator_id = creator_id
        self.original_filename = original_filename
        self.original_extension = original_extension
        self.segments = []  # Tracks tuples: (index, segment_hash, threat_level)
        self.version = version
        self.timestamp = int(datetime.now(timezone.utc).timestamp())
        self.cluster_hash = None
        self.replication_controller = ReplicationController(
            min_replication=3,
            demand_threshold=10,
            network_hyphens=["hyphen1", "hyphen2"],
        )

    def add_segment(self, segment_hash: str, index: int, threat_level: int = 0):
        """
        Adds a segment to the cluster and handles replication for high-threat levels.

        Args:
            segment_hash (str): Unique hash for the segment.
            index (int): Segment position in the sequence.
            threat_level (int): Adaptive replication level for high-threat segments.
        """
        self.segments.append((index, segment_hash, threat_level))
        logger.debug(
            f"Added segment - hash: {segment_hash}, index: {index}, threat level: {threat_level}"
        )

        if threat_level > 0:
            replicator = ThreatBasedReplication(
                self.replication_controller.replication_manager
            )
            replicator.adaptive_threat_replication(
                segment_hash, threat_level, min_replication=3
            )

        logger.info(
            f"Segment {segment_hash} added to cluster at index {index} with threat level {threat_level}."
        )

    def save_cluster_metadata(self, base_dir: str):
        """
        Saves the cluster's metadata as a `.seigr` Protobuf file.

        Args:
            base_dir (str): Directory for storing the `.seigr` file.
        """
        self.segments.sort(key=lambda x: x[0])  # Ensure segments are sorted by index
        self.cluster_hash = self.generate_cluster_hash()
        cluster_filename = f"{self.cluster_hash}.seigr"
        cluster_path = os.path.join(base_dir, cluster_filename)

        # Prepare metadata structure for the cluster
        cluster_proto = SeedDotSeigr(
            creator_id=self.creator_id,
            cluster_hash=self.cluster_hash,
            timestamp=self.timestamp,
            version=self.version,
            original_filename=self.original_filename or "",
            original_extension=self.original_extension or "",
        )

        for index, segment_hash, threat_level in self.segments:
            segment_meta = cluster_proto.segments.add()
            segment_meta.index = index
            segment_meta.segment_hash = segment_hash
            segment_meta.threat_level = threat_level

        os.makedirs(base_dir, exist_ok=True)
        try:
            with open(cluster_path, "wb") as f:
                f.write(cluster_proto.SerializeToString())
            logger.info(f"Cluster metadata saved successfully at {cluster_path}")
        except IOError as e:
            logger.error(f"Failed to save cluster metadata at {cluster_path}: {e}")
            raise

    def generate_cluster_hash(self) -> str:
        """
        Generates a unique SHA-256 hash for the cluster based on ordered segment hashes.

        Returns:
            str: Hash representing the unique identifier of the cluster.
        """
        combined_hash_input = "".join([hash for _, hash, _ in sorted(self.segments)])
        cluster_hash = hypha_hash(combined_hash_input.encode())
        logger.debug(f"Generated cluster hash: {cluster_hash}")
        return cluster_hash

    def log_cluster_action(self, action: str):
        """
        Logs cluster actions for lineage and auditing.

        Args:
            action (str): Description of the cluster-related action.
        """
        lineage_entry = {
            "action": action,
            "creator_id": self.creator_id,
            "cluster_hash": self.cluster_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"Cluster action logged: {lineage_entry}")

    def verify_cluster_integrity(self, reference_hash: str) -> bool:
        """
        Validates the cluster's integrity by comparing the generated hash with a reference hash.

        Args:
            reference_hash (str): Expected hash for verification.

        Returns:
            bool: True if the cluster hash matches the reference hash; otherwise False.
        """
        if not self.cluster_hash:
            self.cluster_hash = self.generate_cluster_hash()

        is_valid = self.cluster_hash == reference_hash
        if is_valid:
            logger.info(
                f"Integrity verification successful for cluster {self.cluster_hash}"
            )
        else:
            logger.warning(
                f"Integrity verification failed for cluster {self.cluster_hash}. Expected {reference_hash}."
            )
        return is_valid


class ClusterLinkManager:
    """
    Manages primary and secondary links for Seigr segments within a cluster.
    """

    def __init__(self):
        self.primary_link = None
        self.secondary_links = []

    def update_links(self, primary_link: str, secondary_links: list):
        """
        Sets primary and secondary links for segments in the Seigr system.

        Args:
            primary_link (str): Primary link hash for the segment.
            secondary_links (list): List of secondary link hashes.
        """
        self.primary_link = primary_link
        self.secondary_links = secondary_links
        logger.debug(
            f"Updated primary link to {primary_link} and secondary links to {secondary_links}"
        )

    def get_links(self) -> dict:
        """
        Retrieves the current primary and secondary links for the segment.

        Returns:
            dict: Dictionary containing 'primary' and 'secondary' link details.
        """
        return {"primary": self.primary_link, "secondary": self.secondary_links}
