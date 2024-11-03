import os
import json
import logging
from .seigr_file import SeigrFile
from .seigr_constants import CLUSTER_LIMIT, HEADER_SIZE
from src.crypto.hypha_crypt import generate_hash

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeigrClusterManager:
    def __init__(self, creator_id: str):
        self.creator_id = creator_id
        self.associated_segments = []
        self.cluster_hash = generate_hash(creator_id)
    
    def add_segment(self, segment_hash: str):
        """Adds a new segment hash to the cluster, checking the cluster limit."""
        if len(self.associated_segments) < CLUSTER_LIMIT:
            self.associated_segments.append(segment_hash)
            logger.debug(f"Added segment {segment_hash} to cluster.")
        else:
            logger.warning("Cluster limit reached; additional clusters are needed.")
    
    def save_cluster(self, base_dir: str):
        """Saves the current cluster data to disk."""
        cluster_data = {
            "creator_id": self.creator_id,
            "cluster_hash": self.cluster_hash,
            "associated_segments": self.associated_segments,
        }
        filename = f"{self.cluster_hash}.cluster.json"
        file_path = os.path.join(base_dir, filename)
        
        try:
            with open(file_path, 'w') as f:
                json.dump(cluster_data, f, indent=4)
            logger.info(f"Cluster saved at {file_path}")
        except Exception as e:
            logger.error(f"Failed to save cluster: {e}")
            raise
