import os
import xml.etree.ElementTree as ET
import logging
from src.crypto.hypha_crypt import generate_hash
from .seigr_constants import SEIGR_SIZE, HEADER_SIZE

# Constants
CLUSTER_LIMIT = SEIGR_SIZE - HEADER_SIZE  # Max allowable size for segments in a primary seed file

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeedDotSeigr:
    def __init__(self, root_hash: str):
        """
        Initializes SeedDotSeigr as the central seed for segment indexing and management.

        Args:
            root_hash (str): Root hash for the seed file's primary identifier.
        """
        self.root_hash = root_hash
        self.associated_segments = []  # Stores (index, segment_hash) tuples
        self.cluster_hashes = []       # References for secondary clusters
        self.seed_hash = generate_hash(root_hash)  # Seed cluster's primary identifier
        self.secondary_cluster_active = False      # Tracks if secondary clusters are required
        logger.debug(f"Initialized SeedDotSeigr with root hash {self.root_hash} and seed hash {self.seed_hash}")

    def add_segment(self, segment_hash: str, index: int):
        """
        Adds a segment hash to the primary cluster, or triggers creation of a secondary cluster if limit is reached.

        Args:
            segment_hash (str): Unique hash of the segment.
            index (int): Segment index in the original sequence.
        """
        if segment_hash not in [seg[1] for seg in self.associated_segments]:
            current_size = len(self.associated_segments) * HEADER_SIZE
            if current_size < CLUSTER_LIMIT:
                self.associated_segments.append((index, segment_hash))
                logger.info(f"Segment {segment_hash} (Index {index}) added to primary cluster.")
            else:
                logger.warning("Primary cluster limit reached; creating new secondary cluster.")
                self.create_new_cluster(segment_hash, index)

    def create_new_cluster(self, segment_hash: str, index: int):
        """
        Creates a new secondary cluster for additional segments beyond the primary cluster's capacity.

        Args:
            segment_hash (str): Hash of the segment triggering the secondary cluster.
            index (int): Index of the segment.
        """
        secondary_cluster = SeedDotSeigr(self.root_hash)
        secondary_cluster.add_segment(segment_hash, index)
        secondary_cluster_path = secondary_cluster.save_to_disk("clusters")

        self.cluster_hashes.append(secondary_cluster_path)
        self.secondary_cluster_active = True
        logger.info(f"Secondary cluster created with seed hash {secondary_cluster.seed_hash} for segment {segment_hash}")

    def save_to_disk(self, directory: str) -> str:
        """
        Saves the seed cluster metadata in XML, including segment data, cluster references, and root identifiers.

        Args:
            directory (str): Path to save the XML file.

        Returns:
            str: File path of the saved seed file.
        """
        seed_file_name = f"{self.seed_hash}.seed_seigr.xml"
        seed_file_path = os.path.join(directory, seed_file_name)

        # XML structure setup
        root = ET.Element("SeedCluster")

        # Immutable fields section
        immutable_fields = ET.SubElement(root, "ImmutableFields")
        ET.SubElement(immutable_fields, "RootHash").text = self.root_hash
        ET.SubElement(immutable_fields, "SeedHash").text = self.seed_hash

        # Mutable fields section for cluster linking
        mutable_fields = ET.SubElement(root, "MutableFields")
        secondary_clusters_elem = ET.SubElement(mutable_fields, "SecondaryClusters")
        for cluster_path in self.cluster_hashes:
            ET.SubElement(secondary_clusters_elem, "ClusterReference", path=cluster_path)

        # Segment information section for indexing within the cluster
        segments_elem = ET.SubElement(root, "Segments")
        for index, segment_hash in sorted(self.associated_segments):
            ET.SubElement(segments_elem, "Segment", hash=segment_hash, index=str(index))

        # Ensure the target directory exists
        os.makedirs(directory, exist_ok=True)

        # Write XML structure to disk with error handling
        try:
            tree = ET.ElementTree(root)
            tree.write(seed_file_path, encoding="utf-8", xml_declaration=True)
            logger.info(f"Seed cluster file saved at {seed_file_path}")
            return seed_file_path
        except Exception as e:
            logger.error(f"Failed to save seed cluster file: {e}")
            raise

    def generate_cluster_report(self) -> dict:
        """
        Generates a detailed report of the cluster, including segment details and secondary clusters.

        Returns:
            dict: Cluster report containing segment and cluster information.
        """
        cluster_report = {
            "root_hash": self.root_hash,
            "seed_hash": self.seed_hash,
            "segments": [{"index": index, "hash": segment_hash} for index, segment_hash in self.associated_segments],
            "secondary_clusters": self.cluster_hashes,
            "secondary_cluster_active": self.secondary_cluster_active
        }
        logger.debug("Cluster report generated.")
        return cluster_report

    def load_from_xml(self, file_path: str):
        """
        Loads cluster information from an XML seed file, reconstructing the seed's state.

        Args:
            file_path (str): Path to the seed XML file to load.
        """
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Load immutable fields
            self.root_hash = root.find("ImmutableFields/RootHash").text
            self.seed_hash = root.find("ImmutableFields/SeedHash").text

            # Load mutable fields
            self.cluster_hashes = [
                cluster.get("path") for cluster in root.findall("MutableFields/SecondaryClusters/ClusterReference")
            ]

            # Load segments
            self.associated_segments = [
                (int(segment.get("index")), segment.get("hash")) for segment in root.findall("Segments/Segment")
            ]

            logger.info(f"Cluster data successfully loaded from {file_path}")
        except Exception as e:
            logger.error(f"Failed to load cluster data from {file_path}: {e}")
            raise

    def display_cluster_info(self):
        """
        Prints detailed information about the cluster, including all associated segments and secondary clusters.
        """
        print(f"=== Seed Cluster Information ===")
        print(f"Root Hash: {self.root_hash}")
        print(f"Seed Hash: {self.seed_hash}")
        print("Segments:")
        for index, segment_hash in sorted(self.associated_segments):
            print(f"  - Segment Index: {index}, Hash: {segment_hash}")
        if self.secondary_cluster_active:
            print("Secondary Clusters:")
            for cluster_path in self.cluster_hashes:
                print(f"  - Cluster Path: {cluster_path}")
        print("================================")
        logger.info("Cluster information displayed.")
