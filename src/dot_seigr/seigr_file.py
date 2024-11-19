import os
import logging
from datetime import datetime, timezone
from src.crypto.hypha_crypt import HyphaCrypt
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import FileMetadata
from dot_seigr.seigr_constants import SEIGR_VERSION
from src.dot_seigr.capsule.seigr_metadata import MetadataManager
from src.dot_seigr.access_control import AccessControlManager
from dot_seigr.temporal.temporal_layer_manager import TemporalLayerManager
from src.dot_seigr.capsule.seigr_coordinate import CoordinateManager
from src.dot_seigr.serialization_manager import SerializationManager
from src.dot_seigr.capsule.seigr_link_manager import LinkManager
from src.dot_seigr.capsule.seigr_integrity_manager import IntegrityManager
from typing import Optional

logger = logging.getLogger(__name__)


class SeigrFile:
    """
    Represents a Seigr file or segment within Seigr's decentralized ecosystem, managing data integrity,
    metadata, access control, temporal layers, and serialization.
    """

    def __init__(
        self, data: bytes, creator_id: str, index: int, file_type: str = "senary"
    ):
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

        # Initialize modular components
        self.hypha_crypt = HyphaCrypt(
            data, str(index), use_senary=(file_type == "senary")
        )
        self.metadata_manager = MetadataManager(self.creator_id, version=self.version)
        self.access_control_manager = AccessControlManager(self.creator_id)
        self.temporal_layer_manager = TemporalLayerManager(self.index)
        self.coordinate_manager = CoordinateManager(self.index)
        self.serialization_manager = SerializationManager()
        self.link_manager = LinkManager()
        self.integrity_manager = IntegrityManager(self.data, self.hypha_crypt)

        # Set up metadata and initial hash
        self.metadata: Optional[FileMetadata] = None
        self._initialize_metadata()
        logger.info(
            f"Initialized SeigrFile for creator {self.creator_id} as {self.file_type} type"
        )

    def _initialize_metadata(self):
        """
        Initializes metadata for the Seigr file, including file versioning and creator information.
        """
        self.metadata = self.metadata_manager.generate_file_metadata(
            original_filename=f"{self.creator_id}_file",
            original_extension=".seigr",
            segments=[
                self.index
            ],  # Placeholder for segments; to be replaced with actual segment data
        )
        logger.debug(f"Initial metadata generated: {self.metadata}")

    def set_links(self, primary_link: str, secondary_links: list):
        """
        Configures primary and secondary links for the Seigr file, supporting modular linkage.

        Args:
            primary_link (str): Primary link hash for the file.
            secondary_links (list): List of secondary link hashes.
        """
        self.link_manager.set_links(primary_link, secondary_links)
        logger.debug(
            f"Links set - primary: {primary_link}, secondary: {secondary_links}"
        )

    def add_temporal_layer(self):
        """
        Creates a new temporal layer snapshot to track historical data states.
        """
        self.temporal_layer_manager.add_layer(self.metadata, self.data)
        logger.info("New temporal layer added to SeigrFile")

    def add_coordinate_index(self, x: int, y: int, z: int):
        """
        Sets a 3D coordinate index for the Seigr file, supporting spatial data structuring.

        Args:
            x (int): X-coordinate.
            y (int): Y-coordinate.
            z (int): Z-coordinate.
        """
        self.coordinate_manager.set_coordinates(x=x, y=y, z=z)
        logger.debug(f"Coordinate index set to ({x}, {y}, {z})")

    def compute_integrity(self) -> str:
        """
        Computes and returns the integrity hash for the Seigr file based on its metadata and data.

        Returns:
            str: Computed integrity hash.
        """
        integrity_hash = self.integrity_manager.compute_integrity(self.metadata)
        logger.info(f"Integrity hash computed: {integrity_hash}")
        return integrity_hash

    def save_to_disk(self, base_dir: str, use_cbor: bool = False) -> str:
        """
        Serializes and saves the Seigr file to disk in the specified directory.

        Args:
            base_dir (str): Base directory for saving the file.
            use_cbor (bool): Whether to use CBOR encoding for the saved file.

        Returns:
            str: Full path to the saved file.

        Raises:
            IOError: If the file could not be saved.
        """
        try:
            file_path = self.serialization_manager.save(self, base_dir, use_cbor)
            logger.info(f"SeigrFile saved to {file_path}")
            return file_path
        except IOError as e:
            logger.error(f"Failed to save SeigrFile to disk at {base_dir}: {e}")
            raise IOError(f"Failed to save SeigrFile to disk at {base_dir}") from e
