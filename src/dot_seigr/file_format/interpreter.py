import logging
from .metadata import MetadataManager
from .encoder import SeigrEncoder
from .decoder import SeigrDecoder
from .manager import SeigrClusterManager
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import FileMetadata  # Import Protobuf definitions for metadata

logger = logging.getLogger(__name__)

class SeigrInterpreter:
    def __init__(self, version="1.0"):
        """
        Initializes the SeigrInterpreter for handling and interpreting .seigr metadata and segments.

        Args:
            version (str): Version of the protocol to enforce (default is "1.0").
        """
        self.version = version
        self.metadata_manager = MetadataManager(version=version)
        logger.info(f"SeigrInterpreter initialized for version {version}")

    def interpret_segment(self, segment_metadata: FileMetadata):
        """
        Interprets an individual segment's metadata and applies necessary operations.

        Args:
            segment_metadata (FileMetadata): Protobuf metadata for a single .seigr segment.

        Returns:
            FileMetadata: Parsed metadata with applied transformations.
        """
        logger.debug(f"Interpreting segment metadata for index {segment_metadata.segment_index}")

        if not segment_metadata.segment_hash:
            logger.warning(f"Missing segment hash for segment at index {segment_metadata.segment_index}")
            return None

        logger.info(f"Interpreted segment with index {segment_metadata.segment_index} and hash {segment_metadata.segment_hash}")
        return segment_metadata

    def interpret_file_metadata(self, file_metadata: FileMetadata):
        """
        Interprets the file-level metadata for a .seigr file.

        Args:
            file_metadata (FileMetadata): The complete metadata Protobuf for a .seigr file.

        Returns:
            FileMetadata: Parsed and validated file metadata.
        """
        logger.debug("Interpreting file metadata for .seigr file.")

        # Validate metadata using MetadataManager
        if not self.metadata_manager.validate_metadata(file_metadata):
            logger.error("File metadata validation failed.")
            return None

        logger.info(f"File metadata interpreted for {file_metadata.original_filename} with {file_metadata.total_segments} segments.")
        return file_metadata

    def validate_version_compatibility(self, metadata_version: str) -> bool:
        """
        Validates the compatibility of a .seigr file's metadata with the current protocol version.

        Args:
            metadata_version (str): Version found in the metadata.

        Returns:
            bool: True if compatible, False otherwise.
        """
        compatible_versions = ["1.0", "1.1"]

        if metadata_version not in compatible_versions:
            logger.warning(f"Metadata version {metadata_version} is not compatible with protocol version {self.version}")
            return False
        logger.info(f"Metadata version {metadata_version} is compatible with protocol version {self.version}")
        return True

    def expand_capabilities(self, metadata_version: str):
        """
        Allows extensions and upgrades based on metadata version, ensuring forward compatibility.

        Args:
            metadata_version (str): The version to expand capabilities for.
        """
        if metadata_version == "1.1":
            logger.info("Activating extended capabilities for version 1.1")
            # Example: Enable advanced metadata handling or encoding features for version 1.1
        logger.info("Capabilities expansion complete.")

    def decode_segments(self, cluster_files: list, base_dir: str) -> str:
        """
        Decodes segments using SeigrDecoder, reassembles data, and verifies integrity.

        Args:
            cluster_files (list): List of cluster files to decode.
            base_dir (str): Directory where cluster files and segments are located.

        Returns:
            str: Path to the reassembled decoded file, or None if decoding fails.
        """
        decoder = SeigrDecoder(cluster_files, base_dir)
        decoded_file_path = decoder.decode()

        if decoded_file_path:
            logger.info(f"Decoded file saved at {decoded_file_path}")
        else:
            logger.warning("Failed to decode the file.")

        return decoded_file_path

    def encode_data(self, data: bytes, creator_id: str, base_dir: str, original_filename: str) -> str:
        """
        Encodes data into .seigr segments, manages clustering, and saves metadata.

        Args:
            data (bytes): The binary data to encode.
            creator_id (str): Unique ID for the data creator.
            base_dir (str): Directory for saving the encoded segments.
            original_filename (str): The name of the original file.

        Returns:
            str: Path to the cluster file containing encoded segments.
        """
        encoder = SeigrEncoder(data, creator_id, base_dir, original_filename)
        encoder.encode()

        # Save cluster metadata after encoding
        cluster_manager = SeigrClusterManager(creator_id, original_filename)
        cluster_file_path = cluster_manager.save_cluster(base_dir)
        logger.info(f"Encoded data stored in cluster file at {cluster_file_path}")
        
        return cluster_file_path

    def load_and_validate_metadata(self, metadata_file: str) -> FileMetadata:
        """
        Loads metadata from file and validates it against the protocol specifications.

        Args:
            metadata_file (str): Path to the metadata Protobuf file.

        Returns:
            FileMetadata: Validated metadata Protobuf, or None if validation fails.
        """
        metadata = self.metadata_manager.load_metadata(metadata_file)

        # Verify version compatibility
        metadata_version = metadata.version
        if not self.validate_version_compatibility(metadata_version):
            logger.error("Loaded metadata is not compatible with the current protocol version.")
            return None

        # Process and expand capabilities based on version
        self.expand_capabilities(metadata_version)

        return metadata

    def log_access(self, metadata: FileMetadata, hyphen_id: str):
        """
        Logs access to a .seigr segment or file, updating access logs.

        Args:
            metadata (FileMetadata): Metadata Protobuf to log access for.
            hyphen_id (str): Unique identifier of the accessing hyphen.
        """
        self.metadata_manager.update_access_log(metadata, hyphen_id)
        logger.debug(f"Access logged for hyphen {hyphen_id} in metadata.")
