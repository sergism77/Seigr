import logging
from .metadata_interpreter import MetadataInterpreter
from .data_interpreter import DataInterpreter  # Renamed to reflect visualization responsibilities
from .compatibility import VersionCompatibility
from dot_seigr.capsule.seigr_manager import SeigrClusterManager
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import FileMetadata, SegmentMetadata

logger = logging.getLogger(__name__)

class CapsuleInterpreter:
    """
    Core interpreter for managing and processing `.seigr` capsules.
    Manages metadata interpretation, encoding/decoding, and version compatibility.
    """

    def __init__(self, version="1.0"):
        """
        Initializes the CapsuleInterpreter for managing `.seigr` capsule operations.
        
        Args:
            version (str): Protocol version to enforce (default is "1.0").
        """
        self.version = version
        self.metadata_interpreter = MetadataInterpreter(version)
        self.data_interpreter = DataInterpreter(creator_id="default")  # Initialize with placeholder or configurable ID
        self.version_compatibility = VersionCompatibility()
        logger.info(f"CapsuleInterpreter initialized for protocol version {version}")

    def interpret_segment_metadata(self, segment_metadata: SegmentMetadata) -> dict:
        """
        Parses and validates individual segment metadata, preparing it for display.
        
        Args:
            segment_metadata (SegmentMetadata): Metadata for a single segment.
        
        Returns:
            dict: Formatted segment metadata for display, or None if validation fails.
        """
        validated_metadata = self.metadata_interpreter.parse_and_validate_segment(segment_metadata)
        if validated_metadata:
            display_data = self.data_interpreter.format_metadata_for_display(validated_metadata)
            logger.debug(f"Segment metadata validated and prepared for display.")
            return display_data
        else:
            logger.error("Segment metadata validation failed.")
            return None

    def interpret_file_metadata(self, file_metadata: FileMetadata) -> dict:
        """
        Parses and validates file-level metadata for a `.seigr` capsule, preparing it for display.
        
        Args:
            file_metadata (FileMetadata): The capsule's file metadata.
        
        Returns:
            dict: Formatted file metadata for display, or None if validation fails.
        """
        validated_metadata = self.metadata_interpreter.parse_and_validate_file(file_metadata)
        if validated_metadata:
            display_data = self.data_interpreter.format_metadata_for_display(validated_metadata)
            logger.debug(f"File metadata validated and prepared for display.")
            return display_data
        else:
            logger.error("File metadata validation failed.")
            return None

    def decode_segments(self, cluster_files: list, base_dir: str) -> list:
        """
        Decodes and prepares data from segments in a `.seigr` cluster for display.
        
        Args:
            cluster_files (list): List of cluster files.
            base_dir (str): Directory containing the files.
        
        Returns:
            list: Decoded segment data, prepared for visualization, or an empty list if decoding fails.
        """
        try:
            decoded_data = []
            for cluster_file in cluster_files:
                segment_data = self.data_interpreter.load_segment(cluster_file, base_dir)  # Load and decode segment
                formatted_data = self.data_interpreter.format_segment_for_display(segment_data)
                decoded_data.append(formatted_data)
            logger.info("Segments successfully decoded and formatted for display.")
            return decoded_data
        except Exception as e:
            logger.error(f"Decoding and formatting segments failed: {e}")
            return []

    def encode_data(self, data: bytes, creator_id: str, base_dir: str, original_filename: str) -> str:
        """
        Encodes raw data into segments for a `.seigr` capsule.
        
        Args:
            data (bytes): Raw data to encode.
            creator_id (str): ID for data creator.
            base_dir (str): Directory for storing segments.
            original_filename (str): Original file name for metadata.
        
        Returns:
            str: Path to the cluster file containing encoded segments, or None if encoding fails.
        """
        try:
            encoded_segments = self.data_interpreter.encode_data_to_segments(data)
            cluster_manager = SeigrClusterManager(creator_id, original_filename)
            cluster_path = cluster_manager.save_cluster_metadata(base_dir, encoded_segments)
            logger.info(f"Data successfully encoded and saved at {cluster_path}")
            return cluster_path
        except Exception as e:
            logger.error(f"Encoding data failed: {e}")
            return None

    def load_and_validate_metadata(self, metadata_file: str) -> dict:
        """
        Loads and validates metadata from a file, ensuring version compatibility.
        
        Args:
            metadata_file (str): Path to the metadata file.
        
        Returns:
            dict: Formatted metadata for display, or None if incompatible.
        """
        try:
            metadata = self.metadata_interpreter.load_metadata(metadata_file)
            if self.version_compatibility.is_compatible(metadata.version, self.version):
                self.version_compatibility.extend_capabilities(metadata.version)
                display_data = self.data_interpreter.format_metadata_for_display(metadata)
                logger.info("Metadata loaded, validated, and prepared for display.")
                return display_data
            else:
                logger.error("Metadata version is not compatible with the current protocol version.")
                return None
        except Exception as e:
            logger.error(f"Loading and validating metadata failed: {e}")
            return None

    def log_access(self, metadata: FileMetadata, hyphen_id: str):
        """
        Logs access to a segment or file, updating access logs in metadata.
        
        Args:
            metadata (FileMetadata): Metadata object to update.
            hyphen_id (str): Identifier for the accessing entity.
        """
        try:
            self.metadata_interpreter.update_access_log(metadata, hyphen_id)
            logger.debug(f"Access logged for hyphen {hyphen_id}.")
        except Exception as e:
            logger.error(f"Failed to log access for hyphen {hyphen_id}: {e}")
