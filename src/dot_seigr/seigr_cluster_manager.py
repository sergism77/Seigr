import os
import xml.etree.ElementTree as ET
import logging
import time
from datetime import datetime
from src.crypto.hypha_crypt import hypha_hash
from .replication import adaptive_replication

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
        self.associated_segments = []
        self.version = version
        self.timestamp = int(time.time())  # Creation timestamp

    def add_segment(self, segment_hash: str, index: int, threat_level=0):
        """
        Adds a segment hash with its index and manages adaptive replication based on threat level.

        Args:
            segment_hash (str): Unique hash of the segment.
            index (int): Position of the segment in the original file sequence.
            threat_level (int): Indicator of the segment's risk status for replication adjustment.
        """
        # Append segment data to the cluster
        self.associated_segments.append((index, segment_hash, threat_level))

        # Adaptive replication for high-threat segments
        if threat_level > 0:
            adaptive_replication(segment_hash, threat_level, len(self.associated_segments), min_replication=3)
        
        logger.info(f"Segment {segment_hash} (Index {index}, Threat Level {threat_level}) added to cluster.")

    def save_cluster(self, base_dir):
        """Save cluster metadata with indexing, filename, and additional fields."""
        # Sort segments by index to ensure correct order
        self.associated_segments.sort(key=lambda x: x[0])

        # Generate the cluster hash for the collection of segments
        cluster_hash = self.generate_cluster_hash()
        cluster_filename = f"{cluster_hash}.cluster.xml"
        cluster_path = os.path.join(base_dir, cluster_filename)

        # XML structure setup
        root = ET.Element("Cluster")
        
        # Immutable fields
        ET.SubElement(root, "CreatorID").text = self.creator_id
        ET.SubElement(root, "ClusterHash").text = cluster_hash
        ET.SubElement(root, "Timestamp").text = str(self.timestamp)
        ET.SubElement(root, "Version").text = self.version

        # Original file metadata (if available)
        if self.original_filename and self.original_extension:
            ET.SubElement(root, "OriginalFilename").text = self.original_filename
            ET.SubElement(root, "OriginalExtension").text = self.original_extension

        # Segment information with indexing
        segments_elem = ET.SubElement(root, "Segments")
        for index, segment_hash in self.associated_segments:
            ET.SubElement(segments_elem, "Segment", hash=segment_hash, index=str(index))

        # Save to XML file
        tree = ET.ElementTree(root)
        tree.write(cluster_path, encoding="utf-8", xml_declaration=True)
        logger.info(f"Cluster metadata saved at {cluster_path}")

    def generate_cluster_hash(self):
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
