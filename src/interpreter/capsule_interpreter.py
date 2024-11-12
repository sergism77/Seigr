import logging
from .metadata_interpreter import MetadataInterpreter
from .encoding import SeigrEncoder, SeigrDecoder
from .compatibility import VersionCompatibility
from dot_seigr.capsule.seigr_manager import SeigrClusterManager
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import FileMetadata

logger = logging.getLogger(__name__)

class CapsuleInterpreter:
    """
    Core interpreter for managing and processing `.seigr` capsules.
    Handles metadata interpretation, encoding/decoding, and version compatibility.
    """

    def __init__(self, version="1.0"):
        """
        Initializes the CapsuleInterpreter for managing `.seigr` capsule operations.

        Args:
            version (str): Protocol version to enforce (default is "1.0").
        """
        self.version = version
        self.metadata_interpreter = MetadataInterpreter(version)
        self.version_compatibility = VersionCompatibility()
        logger.info(f"CapsuleInterpreter initialized for protocol version {version}")

    def interpret_segment_metadata(self, segment_metadata: FileMetadata) -> FileMetadata:
        """
        Parses and validates individual segment metadata.

        Args:
            segment_metadata (FileMetadata): Metadata for a single segment.

        Returns:
            FileMetadata: Validated segment metadata or None if validation fails.
        """
        return self.metadata_interpreter.parse_and_validate_segment(segment_metadata)

    def interpret_file_metadata(self, file_metadata: FileMetadata) -> FileMetadata:
        """
        Parses and validates file-level metadata for a `.seigr` capsule.

        Args:
            file_metadata (FileMetadata): The capsule's file metadata.

        Returns:
            FileMetadata: Validated file metadata, or None if validation fails.
        """
        return self.metadata_interpreter.parse_and_validate_file(file_metadata)

    def decode_segments(self, cluster_files: list, base_dir: str) -> str:
        """
        Decodes and reassembles data from segments in a `.seigr` cluster.

        Args:
            cluster_files (list): List of cluster files.
            base_dir (str): Directory containing the files.

        Returns:
            str: Path to the decoded file, or None if decoding fails.
        """
        decoder = SeigrDecoder(cluster_files, base_dir)
        return decoder.decode()

    def encode_data(self, data: bytes, creator_id: str, base_dir: str, original_filename: str) -> str:
        """
        Encodes raw data into segments for a `.seigr` capsule.

        Args:
            data (bytes): Raw data to encode.
            creator_id (str): ID for data creator.
            base_dir (str): Directory for storing segments.
            original_filename (str): Original file name for metadata.

        Returns:
            str: Path to the cluster file containing encoded segments.
        """
        encoder = SeigrEncoder(data, creator_id, base_dir, original_filename)
        encoder.encode()
        cluster_manager = SeigrClusterManager(creator_id, original_filename)
        return cluster_manager.save_cluster_metadata(base_dir)

    def load_and_validate_metadata(self, metadata_file: str) -> FileMetadata:
        """
        Loads and validates metadata from a file, ensuring version compatibility.

        Args:
            metadata_file (str): Path to the metadata file.

        Returns:
            FileMetadata: Validated metadata, or None if incompatible.
        """
        metadata = self.metadata_interpreter.load_metadata(metadata_file)
        if self.version_compatibility.is_compatible(metadata.version, self.version):
            self.version_compatibility.extend_capabilities(metadata.version)
            return metadata
        logger.error("Metadata version is not compatible with current protocol version.")
        return None

    def log_access(self, metadata: FileMetadata, hyphen_id: str):
        """
        Logs access to a segment or file, updating access logs in metadata.

        Args:
            metadata (FileMetadata): Metadata object to update.
            hyphen_id (str): Identifier for the accessing entity.
        """
        self.metadata_interpreter.update_access_log(metadata, hyphen_id)
        logger.debug(f"Access logged for hyphen {hyphen_id}.")
