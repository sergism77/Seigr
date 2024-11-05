import os
import xml.etree.ElementTree as ET
import logging
from datetime import datetime
from src.crypto.hypha_crypt import hypha_hash
from ..replication import adaptive_replication

logger = logging.getLogger(__name__)

class SeigrClusterManager:
    def __init__(self, creator_id: str, original_filename: str = None, original_extension: str = None, version="1.0"):
        """
        Initializes SeigrClusterManager with optional original filename and extension.
        
        Args:
            creator_id (str): Unique identifier for the creator.
            original_filename (str, optional): Original filename (for metadata).
            original_extension (str, optional): Original file extension (for metadata).
            version (str): Version of the .seigr cluster format.
        """
        self.creator_id = creator_id
        self.original_filename = original_filename
        self.original_extension = original_extension
        self.associated_segments = []  # List of (index, segment_hash, threat_level)
        self.version = version
        self.timestamp = int(datetime.utcnow().timestamp())  # Creation timestamp
        self.cluster_hash = None

    def add_segment(self, segment_hash: str, index: int, threat_level=0):
        """
        Adds a segment hash with its index and manages adaptive replication based on threat level.

        Args:
            segment_hash (str): Unique hash of the segment.
            index (int): Position of the segment in the original file sequence.
            threat_level (int): Indicator of the segment's risk status for replication adjustment.
        """
        self.associated_segments.append((index, segment_hash, threat_level))
        logger.debug(f"Adding segment: hash={segment_hash}, index={index}, threat_level={threat_level}")

        # Adaptive replication for high-threat segments
        if threat_level > 0:
            adaptive_replication(segment_hash, threat_level, len(self.associated_segments), min_replication=3)

        logger.info(f"Segment {segment_hash} (Index {index}, Threat Level {threat_level}) added to cluster.")

    def save_cluster(self, base_dir):
        """
        Save cluster metadata with indexing, filename, and additional fields as an XML structure.

        Args:
            base_dir (str): Directory to save the cluster XML file.
        """
        self.associated_segments.sort(key=lambda x: x[0])  # Ensure order by index
        self.cluster_hash = self.generate_cluster_hash()
        cluster_filename = f"{self.cluster_hash}.cluster.xml"
        cluster_path = os.path.join(base_dir, cluster_filename)

        root = ET.Element("Cluster")
        
        # Immutable fields
        ET.SubElement(root, "CreatorID").text = self.creator_id
        ET.SubElement(root, "ClusterHash").text = self.cluster_hash
        ET.SubElement(root, "Timestamp").text = str(self.timestamp)
        ET.SubElement(root, "Version").text = self.version

        # Original file metadata (optional)
        if self.original_filename and self.original_extension:
            ET.SubElement(root, "OriginalFilename").text = self.original_filename
            ET.SubElement(root, "OriginalExtension").text = self.original_extension

        # Segment information
        segments_elem = ET.SubElement(root, "Segments")
        for index, segment_hash, _ in self.associated_segments:
            ET.SubElement(segments_elem, "Segment", hash=segment_hash, index=str(index))

        # Write XML to file
        os.makedirs(base_dir, exist_ok=True)
        tree = ET.ElementTree(root)
        try:
            tree.write(cluster_path, encoding="utf-8", xml_declaration=True)
            logger.info(f"Cluster metadata saved at {cluster_path}")
        except IOError as e:
            logger.error(f"Failed to save cluster file {cluster_path}: {e}")
            raise

    def generate_cluster_hash(self) -> str:
        """
        Generates a unique hash for the cluster by combining ordered segment hashes.

        Returns:
            str: SHA-256 hash of the concatenated segment hashes.
        """
        combined_hash_input = "".join([hash for _, hash, _ in sorted(self.associated_segments)])
        cluster_hash = hypha_hash(combined_hash_input.encode())
        logger.debug(f"Generated cluster hash: {cluster_hash}")
        return cluster_hash

    def log_cluster_lineage(self, action: str):
        """
        Logs an action related to the cluster's lineage for traceability.

        Args:
            action (str): Description of the action (e.g., "created", "modified", "replicated").
        """
        lineage_entry = {
            "action": action,
            "creator_id": self.creator_id,
            "cluster_hash": self.cluster_hash,
            "timestamp": datetime.utcnow().isoformat(),
        }
        logger.info(f"Cluster lineage log entry: {lineage_entry}")

    def verify_cluster_integrity(self, reference_hash: str) -> bool:
        """
        Verifies the integrity of the cluster by comparing its current hash to a reference hash.

        Args:
            reference_hash (str): Known good hash to verify against.

        Returns:
            bool: True if integrity is confirmed, False otherwise.
        """
        if not self.cluster_hash:
            self.cluster_hash = self.generate_cluster_hash()
        
        valid = self.cluster_hash == reference_hash
        if valid:
            logger.info(f"Integrity check passed for cluster {self.cluster_hash}")
        else:
            logger.warning(f"Integrity check failed for cluster {self.cluster_hash}. Expected {reference_hash}")
        return valid
