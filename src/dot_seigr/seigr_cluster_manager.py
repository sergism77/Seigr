import os
import xml.etree.ElementTree as ET
import logging
from datetime import datetime
from ..crypto.hypha_crypt import hypha_hash
from .replication import adaptive_replication

logger = logging.getLogger(__name__)

class SeigrClusterManager:
    def __init__(self, creator_id: str, version="1.0"):
        """
        Initializes a SeigrClusterManager instance to handle segment clusters.

        Args:
            creator_id (str): Unique ID for the creator of the cluster.
            version (str): Version of the cluster structure.
        """
        self.creator_id = creator_id
        self.associated_segments = []  # Stores segment metadata for cluster
        self.version = version
        self.creation_timestamp = datetime.utcnow().isoformat()  # Creation timestamp in ISO format
        self.cluster_hash = None

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

    def save_cluster(self, base_dir: str, original_filename: str, original_extension: str):
        """
        Saves cluster metadata to an XML file, including segment order, creator information, and file details.

        Args:
            base_dir (str): Directory to save the XML file.
            original_filename (str): Original file's name before segmentation.
            original_extension (str): Original file's extension before segmentation.
        """
        # Sort segments by index
        self.associated_segments.sort(key=lambda x: x[0])

        # Generate the cluster hash if not already generated
        if not self.cluster_hash:
            self.cluster_hash = self.generate_cluster_hash()
        
        cluster_filename = f"{self.cluster_hash}.cluster.xml"
        cluster_path = os.path.join(base_dir, cluster_filename)

        # XML structure setup
        root = ET.Element("Cluster")

        # Immutable fields
        immutable_fields = ET.SubElement(root, "ImmutableFields")
        ET.SubElement(immutable_fields, "CreatorID").text = self.creator_id
        ET.SubElement(immutable_fields, "ClusterHash").text = self.cluster_hash
        ET.SubElement(immutable_fields, "Timestamp").text = self.creation_timestamp
        ET.SubElement(immutable_fields, "Version").text = self.version

        # Original file metadata
        original_file_metadata = ET.SubElement(root, "OriginalFileMetadata")
        ET.SubElement(original_file_metadata, "OriginalFilename").text = original_filename
        ET.SubElement(original_file_metadata, "OriginalExtension").text = original_extension

        # Segment metadata with threat levels
        segments_elem = ET.SubElement(root, "Segments")
        for index, segment_hash, threat_level in self.associated_segments:
            segment_elem = ET.SubElement(segments_elem, "Segment")
            segment_elem.set("index", str(index))
            segment_elem.set("hash", segment_hash)
            segment_elem.set("threat_level", str(threat_level))

        # Save the XML structure to file
        os.makedirs(base_dir, exist_ok=True)
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
