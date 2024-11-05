import os
import logging
from datetime import datetime, timezone
from src.crypto.hypha_crypt import HyphaCrypt
from src.dot_seigr.seigr_constants import HEADER_SIZE, SEIGR_VERSION
from src.dot_seigr.seigr_protocol.encoder import encode_to_senary
from src.dot_seigr.seigr_protocol.metadata import Metadata, TemporalLayer
from src.dot_seigr.seigr_protocol.manager import LinkManager
from src.dot_seigr.seigr_protocol import seigr_file_pb2  # Protobuf for SeigrFile structures

logger = logging.getLogger(__name__)

class SeigrFile:
    def __init__(self, data: bytes, creator_id: str, index: int, file_type="senary"):
        """
        Initializes a SeigrFile instance with protocol-compliant structures for multidimensional data and metadata.
        
        Args:
            data (bytes): Raw data for the segment.
            creator_id (str): Unique identifier for the creator.
            index (int): The segment index in the original file sequence.
            file_type (str): File format type (default: "senary").
        """
        # Initialize encryption, encoding, and metadata
        self.hypha_crypt = HyphaCrypt(data=data, segment_id=str(index))
        self.data = encode_to_senary(data)  # Use protocol-based senary encoding
        self.creator_id = creator_id
        self.index = index
        self.file_type = file_type
        self.hash = self.hypha_crypt.compute_primary_hash()

        # Set up metadata and linking manager
        self.metadata = Metadata(
            creator_id=self.creator_id,
            index=self.index,
            file_type=self.file_type,
            version=SEIGR_VERSION,
            primary_hash=self.hash
        )
        self.link_manager = LinkManager()

        # Initialize temporal layers and access tracking
        self.temporal_layers = []
        self.access_context = {
            "access_count": 0,
            "last_accessed": None,
            "node_access_history": []
        }

    def set_links(self, primary_link: str, secondary_links: list):
        """
        Sets primary and secondary links for multi-path retrieval using the protocol's link manager.
        
        Args:
            primary_link (str): Primary hash link for direct segment linkage.
            secondary_links (list): List of secondary hash links for alternative pathways.
        """
        self.metadata.primary_link = primary_link
        self.metadata.secondary_links = secondary_links
        self.link_manager.update_links(primary_link, secondary_links)
        logger.debug(f"Primary link set to {primary_link} with secondary links: {secondary_links}")

    def add_temporal_layer(self):
        """
        Adds a new temporal layer snapshot to the .seigr file, recording current state.
        """
        data_snapshot = {
            "header": self.metadata.to_dict(),
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
        self.access_context["last_accessed"] = datetime.now(timezone.utc).isoformat()
        self.access_context["node_access_history"].append(node_id)
        logger.debug(f"Access recorded for node {node_id}. Total access count: {self.access_context['access_count']}")

    def generate_hierarchical_hashes(self, depth=6):
        """
        Generates a multi-layered hash tree for the segment data.
        
        Args:
            depth (int): The depth of the hash tree to generate.
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
        Saves the .seigr file as a Protobuf serialized binary file with metadata, data, and temporal layers.

        Args:
            base_dir (str): Directory where the .seigr file will be saved.

        Returns:
            str: Path to the saved .seigr file.
        """
        filename = f"{self.creator_id}_{self.index}.seigr.pb"
        file_path = os.path.join(base_dir, filename)
        logger.debug(f"Preparing to save .seigr file with name: {filename}, path: {file_path}")

        try:
            # Convert to Protobuf structure
            seigr_file_proto = seigr_file_pb2.SeigrFile()
            seigr_file_proto.metadata.creator_id = self.creator_id
            seigr_file_proto.metadata.index = self.index
            seigr_file_proto.metadata.file_type = self.file_type
            seigr_file_proto.metadata.primary_hash = self.hash
            seigr_file_proto.metadata.version = SEIGR_VERSION

            # Add temporal layers
            for layer in self.temporal_layers:
                temp_layer = seigr_file_proto.temporal_layers.add()
                temp_layer.timestamp = layer.timestamp
                temp_layer.data_snapshot.update(layer.data_snapshot)

            # Access context
            seigr_file_proto.access_context.access_count = self.access_context["access_count"]
            seigr_file_proto.access_context.last_accessed = self.access_context["last_accessed"]

            # Links managed by LinkManager
            links = self.link_manager.get_links()
            seigr_file_proto.links.primary_link = links["primary"]
            seigr_file_proto.links.secondary_links.extend(links["secondary"])

            # Ensure base directory exists
            os.makedirs(base_dir, exist_ok=True)
            logger.debug(f"Directory verified: {base_dir}")

            # Serialize and write to disk as a Protobuf binary
            with open(file_path, 'wb') as f:
                f.write(seigr_file_proto.SerializeToString())

            logger.info(f".seigr file successfully saved at {file_path}")
            return file_path

        except (TypeError, ValueError, IOError) as e:
            logger.error(f"Failed to save .seigr file at {file_path}: {e}")
            raise

    def add_coordinate_index(self, x: int, y: int, z: int):
        """
        Adds a 3D coordinate index for multi-layered data positioning.
        
        Args:
            x (int): X-coordinate.
            y (int): Y-coordinate.
            z (int): Z-coordinate.
        """
        self.metadata.coordinate_index = {"x": x, "y": y, "z": z}
        logger.debug(f"Coordinate index set to x: {x}, y: {y}, z: {z}")
