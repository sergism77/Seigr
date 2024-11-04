import os
import json
import logging
from datetime import datetime
from .seigr_constants import HEADER_SIZE, SEIGR_VERSION, SEIGR_SIZE
from ..crypto.hypha_crypt import HyphaCrypt

logger = logging.getLogger(__name__)

class TemporalLayer:
    def __init__(self, data_snapshot, timestamp=None):
        """
        Temporal layer records a snapshot of the .seigr file’s data and metadata at a specific point in time.
        
        Args:
            data_snapshot (dict): Snapshot of the file data and metadata.
            timestamp (str): ISO-formatted timestamp for when this snapshot was created.
        """
        self.data_snapshot = data_snapshot
        self.timestamp = timestamp or datetime.utcnow().isoformat()

    def to_dict(self):
        """Converts the TemporalLayer to a dictionary format."""
        return {
            "timestamp": self.timestamp,
            "data_snapshot": self.data_snapshot
        }

class SeigrFile:
    def __init__(self, data: bytes, creator_id: str, index: int, file_type="senary"):
        """
        Initialize a SeigrFile instance with support for a 4D framework and cryptographic structure.
        
        Args:
            data (bytes): Raw data for the segment.
            creator_id (str): Unique identifier for the creator.
            index (int): The segment index in the original file sequence.
            file_type (str): File format type (default: "senary").
        """
        self.hypha_crypt = HyphaCrypt(data=data, segment_id=str(index))
        self.data = self.hypha_crypt.encode_to_senary(data)
        self.creator_id = creator_id
        self.index = index
        self.file_type = file_type
        self.hash = self.hypha_crypt.compute_primary_hash()

        # Metadata for multidimensional structure
        self.version = SEIGR_VERSION
        self.primary_link = None
        self.secondary_links = []
        self.coordinate_index = None
        self.temporal_layers = []
        self.access_context = {
            "access_count": 0,
            "last_accessed": None,
            "node_access_history": []
        }

    def set_links(self, primary_link: str, secondary_links: list):
        """
        Set primary and secondary links for multi-path retrieval.
        
        Args:
            primary_link (str): Primary hash link for direct segment linkage.
            secondary_links (list): List of secondary hash links for alternative pathways.
        """
        self.primary_link = primary_link
        self.secondary_links = secondary_links
        logger.debug(f"Primary link set to {primary_link} with secondary links: {secondary_links}")

    def add_temporal_layer(self):
        """
        Adds a new temporal layer snapshot to the .seigr file.
        """
        data_snapshot = {
            "header": {
                "version": self.version,
                "creator_id": self.creator_id,
                "file_type": self.file_type,
                "hash": self.hash,
                "index": self.index,
                "header_size": HEADER_SIZE,
                "primary_link": self.primary_link,
                "secondary_links": self.secondary_links,
                "coordinate_index": self.coordinate_index
            },
            "data": self.data
        }
        new_layer = TemporalLayer(data_snapshot)
        self.temporal_layers.append(new_layer)
        logger.info(f"New temporal layer added with timestamp {new_layer.timestamp}")

    def record_access(self, node_id: str):
        """
        Records access context for adaptive replication and access scaling.
        
        Args:
            node_id (str): Unique identifier of the accessing node.
        """
        self.access_context["access_count"] += 1
        self.access_context["last_accessed"] = datetime.utcnow().isoformat()
        self.access_context["node_access_history"].append(node_id)
        logger.debug(f"Access recorded for node {node_id}. Total access count: {self.access_context['access_count']}")

    def generate_hierarchical_hashes(self, depth=6):
        """
        Generates a multi-layered hash tree for the segment data.
        
        Args:
            depth (int): The depth of the hash tree.
        """
        hash_tree = self.hypha_crypt.compute_layered_hashes(layers=depth)
        logger.info(f"Generated hash tree up to depth {depth} for segment {self.index}")
        return hash_tree

    def verify_integrity(self, reference_tree):
        """
        Verifies the integrity of the segment by comparing its hash tree with a reference tree.
        
        Args:
            reference_tree (dict): The hash tree structure to verify against.
        
        Returns:
            bool: True if the hash trees match, False otherwise.
        """
        result = self.hypha_crypt.verify_integrity(reference_tree)
        if result:
            logger.info(f"Integrity verified for segment {self.index}")
        else:
            logger.warning(f"Integrity check failed for segment {self.index}")
        return result

    def save_to_disk(self, base_dir: str) -> str:
        """
        Saves the .seigr file as a structured JSON with metadata, data, and temporal layers.

        Args:
            base_dir (str): Directory where the .seigr file will be saved.

        Returns:
            str: Path to the saved .seigr file.
        """
        filename = f"{self.hash}.seigr"
        file_path = os.path.join(base_dir, filename)

        # Construct the .seigr file content with metadata, data, and temporal layers
        seigr_content = {
            "header": {
                "version": self.version,
                "creator_id": self.creator_id,
                "file_type": self.file_type,
                "hash": self.hash,
                "index": self.index,
                "header_size": HEADER_SIZE,
                "primary_link": self.primary_link,
                "secondary_links": self.secondary_links,
                "coordinate_index": self.coordinate_index
            },
            "data": self.data,
            "temporal_layers": [layer.to_dict() for layer in self.temporal_layers],
            "access_context": self.access_context
        }

        # Ensure directory exists
        os.makedirs(base_dir, exist_ok=True)

        # Write to disk as a JSON file
        with open(file_path, 'w') as f:
            json.dump(seigr_content, f, indent=4)
        
        logger.info(f".seigr file saved at {file_path}")
        return file_path

    def add_coordinate_index(self, x: int, y: int, z: int):
        """
        Adds a 3D coordinate index for multi-layered data positioning.
        
        Args:
            x (int): X-coordinate.
            y (int): Y-coordinate.
            z (int): Z-coordinate.
        """
        self.coordinate_index = {"x": x, "y": y, "z": z}
        logger.debug(f"Coordinate index set to x: {x}, y: {y}, z: {z}")
