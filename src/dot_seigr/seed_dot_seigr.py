import os
import logging
import time
from src.dot_seigr.seigr_protocol import seed_dot_seigr_pb2  # Import compiled Protobuf classes
from src.crypto.hypha_crypt import generate_hash
from .seigr_constants import HEADER_SIZE, SEIGR_SIZE

# Constants
CLUSTER_LIMIT = SEIGR_SIZE - HEADER_SIZE  # Max size for primary cluster

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeedDotSeigr:
    def __init__(self, root_hash: str):
        """
        Initializes SeedDotSeigr as the central seed for indexing and management.
        
        Args:
            root_hash (str): Root hash for the seed file's primary identifier.
        """
        self.root_hash = root_hash
        self.seed_hash = generate_hash(root_hash)  # Unique hash for network ID
        self.cluster = seed_dot_seigr_pb2.SeigrCluster()  # Protobuf structure
        self.cluster.root_hash = self.root_hash
        self.cluster.seed_hash = self.seed_hash
        self.secondary_cluster_active = False
        logger.debug(f"Initialized SeedDotSeigr with root hash {self.root_hash} and seed hash {self.seed_hash}")

    def add_segment(self, segment_hash: str, index: int, threat_level=0):
        """
        Adds a segment to the primary cluster or creates a new cluster if limit is reached.
        
        Args:
            segment_hash (str): Unique hash of the segment.
            index (int): Segment index.
            threat_level (int): Threat level for adaptive replication.
        """
        if self._is_primary_cluster_full():
            logger.warning(f"Primary cluster limit reached, creating a new secondary cluster for segment {segment_hash}.")
            self.create_new_cluster(segment_hash, index, threat_level)
        else:
            segment = self.cluster.segments.add()
            segment.index = index
            segment.hash = segment_hash
            segment.threat_level = threat_level
            logger.info(f"Added segment {segment_hash} (Index {index}, Threat Level {threat_level}) to primary cluster.")

    def _is_primary_cluster_full(self) -> bool:
        """
        Checks if the primary cluster has reached its segment storage limit.

        Returns:
            bool: True if primary cluster is full, otherwise False.
        """
        current_size = len(self.cluster.segments) * HEADER_SIZE
        return current_size >= CLUSTER_LIMIT

    def create_new_cluster(self, segment_hash: str, index: int, threat_level: int = 0):
        """
        Creates a new secondary cluster for segments beyond primary capacity.
        
        Args:
            segment_hash (str): Segment hash initiating new cluster.
            index (int): Segment index.
            threat_level (int): Threat level for adaptive replication.
        """
        secondary_cluster = SeedDotSeigr(self.root_hash)
        secondary_cluster.add_segment(segment_hash, index, threat_level)
        secondary_cluster_path = secondary_cluster.save_to_disk("clusters")
        self.cluster.secondary_clusters.append(secondary_cluster_path)
        self.secondary_cluster_active = True
        logger.info(f"Created secondary cluster with seed hash {secondary_cluster.seed_hash}")

    def save_to_disk(self, directory: str) -> str:
        """
        Serializes the seed data and saves it to disk.
        
        Args:
            directory (str): Directory for storing the seed file.

        Returns:
            str: File path of saved seed file.
        """
        seed_filename = f"{self.seed_hash}.seed_seigr.pb"
        seed_file_path = os.path.join(directory, seed_filename)
        os.makedirs(directory, exist_ok=True)

        try:
            with open(seed_file_path, "wb") as f:
                f.write(self.cluster.SerializeToString())
            logger.info(f"Seed cluster file saved at {seed_file_path}")
            return seed_file_path
        except IOError as e:
            logger.error(f"Failed to save seed cluster file: {e}")
            raise

    def load_from_disk(self, file_path: str):
        """
        Deserializes and loads cluster data from a Protobuf file.
        
        Args:
            file_path (str): Path to the saved seed file.
        """
        try:
            with open(file_path, "rb") as f:
                self.cluster.ParseFromString(f.read())
            logger.info(f"Loaded cluster data from {file_path}")
        except IOError as e:
            logger.error(f"Failed to load cluster data: {e}")
            raise

    def generate_cluster_report(self) -> dict:
        """
        Generates a report of the cluster's structure.
        
        Returns:
            dict: Report with segment details and cluster references.
        """
        report = {
            "root_hash": self.cluster.root_hash,
            "seed_hash": self.cluster.seed_hash,
            "segments": [
                {"index": seg.index, "hash": seg.hash, "threat_level": seg.threat_level}
                for seg in self.cluster.segments
            ],
            "secondary_clusters": list(self.cluster.secondary_clusters),
            "secondary_cluster_active": self.secondary_cluster_active
        }
        logger.debug("Generated cluster report.")
        return report

    def ping_network(self):
        """
        Sends a ping to update active time and connectivity for this seed file.
        """
        timestamp = int(time.time())
        self.cluster.last_ping = timestamp
        logger.info(f"Ping sent at {timestamp}")

    def display_cluster_info(self):
        """
        Prints detailed information about the cluster, including segments and secondary clusters.
        """
        print(f"=== Seed Cluster Information ===")
        print(f"Root Hash: {self.cluster.root_hash}")
        print(f"Seed Hash: {self.cluster.seed_hash}")
        print("Segments:")
        for seg in self.cluster.segments:
            print(f"  - Segment Index: {seg.index}, Hash: {seg.hash}, Threat Level: {seg.threat_level}")
        if self.secondary_cluster_active:
            print("Secondary Clusters:")
            for cluster_path in self.cluster.secondary_clusters:
                print(f"  - Cluster Path: {cluster_path}")
        print("================================")
        logger.info("Displayed cluster information.")
