from typing import Optional, List

from dot_seigr.seigr_constants import SEIGR_VERSION
from dot_seigr.temporal.temporal_layer_manager import TemporalLayerManager
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.integrity_verification import _get_hypha_crypt
from src.dot_seigr.access_control import AccessControlManager
from src.dot_seigr.capsule.seigr_coordinate import SeigrCoordinateManager
from src.dot_seigr.capsule.seigr_integrity_manager import IntegrityManager
from src.dot_seigr.capsule.seigr_link_manager import FileLinkManager
from src.dot_seigr.capsule.seigr_metadata import MetadataManager
from src.dot_seigr.serialization_manager import SerializationManager
from src.logger.secure_logger import secure_logger  # ✅ Now using secure_logger
from src.seigr_protocol.compiled.file_metadata_pb2 import FileMetadata
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity  # ✅ Seigr Alert Levels


class SeigrFile:
    """
    Represents a Seigr file or segment within Seigr's decentralized ecosystem, managing data integrity,
    metadata, access control, temporal layers, and serialization.
    """

    def __init__(self, data: bytes, creator_id: str, index: int, file_type: str = "senary"):
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
        HyphaCrypt = _get_hypha_crypt()
        self.hypha_crypt = HyphaCrypt(data, str(index), use_senary=(file_type == "senary"))
        self.metadata_manager = MetadataManager(self.creator_id, version=self.version)
        self.access_control_manager = AccessControlManager(self.creator_id)
        self.temporal_layer_manager = TemporalLayerManager(self.index)
        self.coordinate_manager = SeigrCoordinateManager(self.index)
        self.serialization_manager = SerializationManager()
        self.link_manager = FileLinkManager()
        self.integrity_manager = IntegrityManager(self.data, self.hypha_crypt)

        # Set up metadata and initial hash
        self.metadata: Optional[FileMetadata] = None
        self._initialize_metadata()

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="SeigrFile",
            message=f"Initialized SeigrFile for creator {self.creator_id} as {self.file_type} type",
        )

    def _initialize_metadata(self) -> None:
        """
        Initializes metadata for the Seigr file, including file versioning and creator information.
        Dynamically tracks segment data for metadata consistency.
        """
        segment_list = [self.index]  # Initialize with the primary segment

        if hasattr(self, "link_manager"):
            linked_segments = self.link_manager.get_links().get("secondary", [])
            segment_list.extend(linked_segments)

        self.metadata = self.metadata_manager.generate_file_metadata(
            original_filename=f"{self.creator_id}_file",
            original_extension=".seigr",
            segments=segment_list,
        )

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_DEBUG,
            category="SeigrFile",
            message=f"Initial metadata generated for SeigrFile: {self.metadata}",
        )

    def set_links(self, primary_link: str, secondary_links: List[str]) -> None:
        """
        Configures primary and secondary links for the Seigr file, supporting modular linkage.

        Args:
            primary_link (str): Primary link hash for the file.
            secondary_links (list): List of secondary link hashes.
        """
        if not isinstance(primary_link, str) or not all(
            isinstance(link, str) for link in secondary_links
        ):
            raise ValueError("Primary link and secondary links must be valid strings.")

        self.link_manager.set_links(primary_link, secondary_links)

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="SeigrFile",
            message=f"Links set for SeigrFile - primary: {primary_link}, secondary: {secondary_links}",
        )

    def add_temporal_layer(self) -> None:
        """
        Creates a new temporal layer snapshot to track historical data states.
        Ensures integrity validation before adding a new layer.
        """
        if not self.metadata:
            raise ValueError("Metadata must be initialized before adding a temporal layer.")

        if not self.compute_integrity():
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_WARNING,
                category="SeigrFile",
                message="Integrity validation failed before adding a temporal layer.",
            )
            raise ValueError("Cannot add a temporal layer due to failed integrity check.")

        self.temporal_layer_manager.add_layer(self.metadata, self.data)

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="SeigrFile",
            message="New temporal layer added to SeigrFile",
        )

    def add_coordinate_index(self, x: int, y: int, z: int) -> None:
        """
        Sets a 3D coordinate index for the Seigr file, supporting spatial data structuring.

        Args:
            x (int): X-coordinate.
            y (int): Y-coordinate.
            z (int): Z-coordinate.
        """
        self.coordinate_manager.set_coordinates(x=x, y=y, z=z)

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="SeigrFile",
            message=f"Coordinate index set to ({x}, {y}, {z})",
        )

    def compute_integrity(self) -> str:
        """
        Computes and returns the integrity hash for the Seigr file based on its metadata and data.

        Returns:
            str: Computed integrity hash.
        """
        if not self.metadata:
            raise ValueError("Metadata must be initialized before computing integrity.")

        integrity_hash = self.integrity_manager.compute_integrity(self.metadata)

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="SeigrFile",
            message=f"Integrity hash computed: {integrity_hash}",
        )

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
        if not isinstance(base_dir, str) or not base_dir:
            raise ValueError("Invalid directory path provided.")

        try:
            file_path = self.serialization_manager.save(self, base_dir, use_cbor)

            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="SeigrFile",
                message=f"SeigrFile saved successfully at {file_path}",
            )

            return file_path
        except IOError as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                category="SeigrFile",
                message=f"Failed to save SeigrFile to disk at {base_dir}: {e}",
            )
            raise IOError(f"Failed to save SeigrFile to disk at {base_dir}") from e
