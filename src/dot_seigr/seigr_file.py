import os
import logging
from datetime import datetime, timezone
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.hash_utils import hypha_hash
from src.dot_seigr.seigr_constants import SEIGR_VERSION
from src.dot_seigr.capsule.seigr_metadata import MetadataManager
from src.dot_seigr.access_control import AccessControlManager
from src.dot_seigr.temporal_layer_manager import TemporalLayerManager
from src.dot_seigr.capsule.seigr_coordinate import CoordinateManager
from src.dot_seigr.serialization_manager import SerializationManager
from src.dot_seigr.capsule.seigr_link_manager import LinkManager
from src.dot_seigr.capsule.seigr_integrity_manager import IntegrityManager

logger = logging.getLogger(__name__)

class SeigrFile:
    def __init__(self, data: bytes, creator_id: str, index: int, file_type="senary"):
        """
        Initializes a SeigrFile with cryptographic, metadata, and modular management components.

        Args:
            data (bytes): Binary data to be managed by the SeigrFile.
            creator_id (str): Unique identifier for the file creator.
            index (int): File or segment index for tracking within Seigr.
            file_type (str): Format type, default is "senary".
        """
        self.data = data
        self.creator_id = creator_id
        self.index = index
        self.file_type = file_type
        self.version = SEIGR_VERSION

        # Initialize modular components with flexibility for adaptation
        self.hypha_crypt = HyphaCrypt(data, str(index), use_senary=(file_type == "senary"))
        self.metadata_manager = MetadataManager(self.creator_id, version=self.version)
        self.access_control_manager = AccessControlManager(self.creator_id)
        self.temporal_layer_manager = TemporalLayerManager(self.index)
        self.coordinate_manager = CoordinateManager(self.index)
        self.serialization_manager = SerializationManager()
        self.link_manager = LinkManager()
        self.integrity_manager = IntegrityManager(self.data, self.hypha_crypt)

        # Set up basic metadata and hash on creation
        self.metadata = None
        self.generate_metadata()
        logger.info(f"Initialized SeigrFile with creator ID {self.creator_id} and file type {self.file_type}")

    def generate_metadata(self):
        """
        Generates metadata for the Seigr file, setting the initial metadata state.
        """
        self.metadata = self.metadata_manager.generate_file_metadata(
            original_filename=f"{self.creator_id}_file",
            original_extension=".seigr",
            segments=[self.index]  # Placeholder for segments; replace with actual data as needed
        )
        logger.debug(f"Metadata generated: {self.metadata}")

    def set_links(self, primary_link: str, secondary_links: list):
        """
        Sets primary and secondary links for file distribution or tracking.

        Args:
            primary_link (str): Primary link hash for the file.
            secondary_links (list): List of secondary link hashes.
        """
        self.link_manager.set_links(primary_link, secondary_links)
        logger.debug(f"Set links with primary {primary_link} and secondary {secondary_links}")

    def add_temporal_layer(self):
        """
        Adds a new temporal layer snapshot for version tracking.
        """
        self.temporal_layer_manager.add_layer(self.metadata, self.data)
        logger.info("Added new temporal layer to SeigrFile")

    def add_coordinate_index(self, x: int, y: int, z: int):
        """
        Sets a 3D coordinate index for the Seigr file, useful for spatial data organization.

        Args:
            x (int): X-coordinate.
            y (int): Y-coordinate.
            z (int): Z-coordinate.
        """
        self.coordinate_manager.set_coordinates(x, y, z)
        logger.debug(f"Coordinate index set to ({x}, {y}, {z})")

    def compute_integrity(self):
        """
        Computes and verifies the integrity of the Seigr file based on its metadata and data.
        """
        integrity_hash = self.integrity_manager.compute_integrity(self.metadata)
        logger.info(f"Computed integrity hash: {integrity_hash}")

    def save_to_disk(self, base_dir: str, use_cbor: bool = False) -> str:
        """
        Serializes and saves the Seigr file to disk.

        Args:
            base_dir (str): Base directory for saving the file.
            use_cbor (bool): Optionally use CBOR encoding for the saved file.

        Returns:
            str: Path to the saved file.
        """
        file_path = self.serialization_manager.save(self, base_dir, use_cbor)
        logger.info(f"SeigrFile saved to disk at {file_path}")
        return file_path
