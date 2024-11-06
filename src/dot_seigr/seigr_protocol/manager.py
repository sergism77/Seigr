import os
import logging
from datetime import datetime, timezone
from src.crypto.hypha_crypt import hypha_hash
from ..replication_threat import ThreatBasedReplication
from ..replication_controller import ReplicationController
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SeedDotSeigr as SeedDotSeigr, SegmentMetadata

logger = logging.getLogger(__name__)

class SeigrClusterManager:
    def __init__(self, creator_id: str, original_filename: str = None, original_extension: str = None, version="1.0"):
        """
        Initializes SeigrClusterManager to handle segment clustering and metadata management.
        
        Args:
            creator_id (str): Unique identifier for the creator.
            original_filename (str, optional): Original filename (for metadata).
            original_extension (str, optional): Original file extension (for metadata).
            version (str): Version of the cluster format.
        """
        self.creator_id = creator_id
        self.original_filename = original_filename
        self.original_extension = original_extension
        self.associated_segments = []  # List of tuples: (index, segment_hash, threat_level)
        self.version = version
        self.timestamp = int(datetime.now(timezone.utc).timestamp())  # Cluster creation timestamp
        self.cluster_hash = None  # To be generated based on segments
        self.replication_controller = ReplicationController(min_replication=3, demand_threshold=10, network_nodes=["node1", "node2"])

    def add_segment(self, segment_hash: str, index: int, threat_level: int = 0):
        """
        Adds a segment to the cluster with replication management for high-threat segments.
        
        Args:
            segment_hash (str): Unique hash of the segment.
            index (int): Position of the segment in the original file sequence.
            threat_level (int): Threat level for adaptive replication.
        """
        self.associated_segments.append((index, segment_hash, threat_level))
        logger.debug(f"Segment added - hash: {segment_hash}, index: {index}, threat_level: {threat_level}")

        # Adaptive replication for high-threat segments
        if threat_level > 0:
            replicator = ThreatBasedReplication(self.replication_controller.replication_manager)
            replicator.adaptive_threat_replication(segment_hash, threat_level, min_replication=3)
        
        logger.info(f"Segment {segment_hash} added to cluster at index {index} with threat level {threat_level}.")

    def save_cluster_metadata(self, base_dir: str):
        """
        Save the cluster metadata as a Protobuf-based .seigr file.
        
        Args:
            base_dir (str): Directory to save the .seigr file.
        """
        self.associated_segments.sort(key=lambda x: x[0])  # Sort segments by index for consistency
        self.cluster_hash = self.generate_cluster_hash()    # Generate cluster hash based on segment order
        cluster_filename = f"{self.cluster_hash}.seigr"
        cluster_path = os.path.join(base_dir, cluster_filename)

        # Protobuf structure for cluster metadata
        cluster_proto = SeedDotSeigr(
            creator_id=self.creator_id,
            cluster_hash=self.cluster_hash,
            timestamp=self.timestamp,
            version=self.version,
            original_filename=self.original_filename or "",
            original_extension=self.original_extension or ""
        )

        # Add segments to Protobuf
        for index, segment_hash, threat_level in self.associated_segments:
            segment_meta = cluster_proto.segments.add()
            segment_meta.index = index
            segment_meta.segment_hash = segment_hash
            segment_meta.threat_level = threat_level

        # Save to .seigr file
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
        Generates a unique hash for the cluster based on ordered segment hashes.
        
        Returns:
            str: SHA-256 hash representing the cluster's unique identifier.
        """
        combined_hash_input = "".join([hash for _, hash, _ in sorted(self.associated_segments)])
        cluster_hash = hypha_hash(combined_hash_input.encode())
        logger.debug(f"Generated cluster hash: {cluster_hash}")
        return cluster_hash

    def log_cluster_action(self, action: str):
        """
        Logs cluster actions (e.g., creation, modification) for lineage tracking.
        
        Args:
            action (str): Description of the action performed on the cluster.
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
        Verifies the integrity of the cluster by comparing with a reference hash.
        
        Args:
            reference_hash (str): Known correct hash for verification.
        
        Returns:
            bool: True if the integrity check passes, False otherwise.
        """
        if not self.cluster_hash:
            self.cluster_hash = self.generate_cluster_hash()
        
        is_valid = self.cluster_hash == reference_hash
        if is_valid:
            logger.info(f"Integrity verification successful for cluster {self.cluster_hash}")
        else:
            logger.warning(f"Integrity verification failed for cluster {self.cluster_hash}. Expected {reference_hash}.")
        return is_valid


class LinkManager:
    def __init__(self):
        """
        Initializes LinkManager to manage primary and secondary links for Seigr segments.
        """
        self.primary_link = None
        self.secondary_links = []

    def update_links(self, primary_link: str, secondary_links: list):
        """
        Updates primary and secondary links for Seigr segments.
        
        Args:
            primary_link (str): Primary link hash for the segment.
            secondary_links (list): List of secondary link hashes.
        """
        self.primary_link = primary_link
        self.secondary_links = secondary_links
        logger.debug(f"Updated primary link to {primary_link} and secondary links to {secondary_links}")

    def get_links(self) -> dict:
        """
        Retrieves the primary and secondary links for the segment.
        
        Returns:
            dict: Dictionary with 'primary' and 'secondary' link information.
        """
        return {
            "primary": self.primary_link,
            "secondary": self.secondary_links
        }
