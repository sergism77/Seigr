# src/dot_seigr/seed_dot_seigr.py

import os
import json
import logging
from src.crypto.hypha_crypt import generate_hash

# Constants
SEIGR_SIZE = 539 * 1024  # Each .seigr file is 539 KB
HEADER_SIZE = 128        # Reserved space in bytes for the header
CLUSTER_LIMIT = SEIGR_SIZE - HEADER_SIZE  # Maximum size for associated segments in a seed file

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeedDotSeigr:
    def __init__(self, root_hash: str):
        """
        Initializes the SeedDotSeigr class with the root hash.
        
        Args:
            root_hash (str): The hash of the root .seigr file that this seed file is managing.
        """
        self.root_hash = root_hash
        self.associated_files = []  # List to track associated .seigr files
        self.cluster_hashes = []    # List to manage additional clusters if needed
        self.seed_hash = generate_hash(root_hash)  # Unique hash for this seed file

    def add_segment(self, segment_hash: str):
        """
        Adds a .seigr file's hash to the list of associated files if space allows.
        
        Args:
            segment_hash (str): Hash of the .seigr segment to add to the seed.
        """
        if segment_hash not in self.associated_files:
            current_size = len(self.associated_files) * HEADER_SIZE
            if current_size < CLUSTER_LIMIT:
                self.associated_files.append(segment_hash)
                logger.info(f"Segment {segment_hash} added to seed file.")
            else:
                logger.warning("Cluster limit reached; creating new seed cluster.")
                self.create_new_cluster(segment_hash)

    def create_new_cluster(self, segment_hash: str):
        """
        Creates a new seed cluster when the current seed file reaches the cluster limit.
        
        Args:
            segment_hash (str): Hash of the segment initiating the new cluster.
        """
        new_cluster = SeedDotSeigr(self.root_hash)
        new_cluster.add_segment(segment_hash)
        new_cluster_hash = new_cluster.save_to_disk("clusters")  # Save to a specific directory for organization
        self.cluster_hashes.append(new_cluster_hash)
        logger.info(f"New cluster created with hash {new_cluster_hash} and segment {segment_hash}")

    def save_to_disk(self, directory: str) -> str:
        """
        Saves the seed .seigr file to disk with all associated segments and cluster references.

        Args:
            directory (str): Directory to save the seed file.
        
        Returns:
            str: Path to the saved seed file.
        """
        seed_content = {
            "header": {
                "root_hash": self.root_hash,
                "seed_hash": self.seed_hash,
                "cluster_hashes": self.cluster_hashes
            },
            "associated_files": self.associated_files
        }

        filename = f"{self.seed_hash}.seed_seigr"
        file_path = os.path.join(directory, filename)

        try:
            with open(file_path, 'w') as file:
                json.dump(seed_content, file, indent=4)
            logger.info(f"Seed .seigr file saved at {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Failed to save seed .seigr file: {e}")
            raise
