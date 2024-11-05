import json
import logging
from datetime import datetime
from src.crypto.hypha_crypt import hypha_hash

logger = logging.getLogger(__name__)

class MetadataManager:
    def __init__(self, creator_id: str, version: str = "1.0"):
        """
        Initializes a MetadataManager to generate and manage metadata for .seigr segments.

        Args:
            creator_id (str): Unique identifier for the creator.
            version (str): Version of the .seigr format.
        """
        self.creator_id = creator_id
        self.version = version

    def generate_segment_metadata(self, index: int, segment_hash: str, primary_link: str = None, secondary_links: list = None, coordinate_index: dict = None):
        """
        Generates metadata for an individual .seigr segment.

        Args:
            index (int): Segment index in the file sequence.
            segment_hash (str): Unique hash of the segment.
            primary_link (str, optional): Primary hash link for direct segment linkage.
            secondary_links (list, optional): List of secondary hash links for alternative pathways.
            coordinate_index (dict, optional): 3D coordinate index for multi-layered data positioning.

        Returns:
            dict: Metadata dictionary for the .seigr segment.
        """
        timestamp = datetime.utcnow().isoformat()

        metadata = {
            "header": {
                "version": self.version,
                "creator_id": self.creator_id,
                "segment_index": index,
                "segment_hash": segment_hash,
                "timestamp": timestamp,
                "primary_link": primary_link,
                "secondary_links": secondary_links or [],
                "coordinate_index": coordinate_index or {}
            }
        }

        logger.debug(f"Generated metadata for segment {index}: {metadata}")
        return metadata

    def generate_file_metadata(self, original_filename: str, original_extension: str, segments: list):
        """
        Generates top-level metadata for a complete .seigr file, combining individual segment metadata.

        Args:
            original_filename (str): The original filename of the data.
            original_extension (str): The original file extension.
            segments (list): List of segment metadata dictionaries.

        Returns:
            dict: Top-level metadata for the complete .seigr file.
        """
        creation_timestamp = datetime.utcnow().isoformat()
        combined_segment_hashes = "".join([segment["header"]["segment_hash"] for segment in segments])
        file_hash = hypha_hash(combined_segment_hashes.encode())

        file_metadata = {
            "file_header": {
                "version": self.version,
                "creator_id": self.creator_id,
                "original_filename": original_filename,
                "original_extension": original_extension,
                "file_hash": file_hash,
                "creation_timestamp": creation_timestamp,
                "total_segments": len(segments)
            },
            "segments": segments
        }

        logger.info(f"Generated file metadata with hash: {file_hash}")
        return file_metadata

    def save_metadata_to_json(self, metadata: dict, file_path: str):
        """
        Saves metadata to a JSON file.

        Args:
            metadata (dict): The metadata dictionary to be saved.
            file_path (str): Path to save the metadata JSON file.

        Raises:
            IOError: If the file cannot be written.
        """
        try:
            with open(file_path, 'w') as f:
                json.dump(metadata, f, indent=4)
            logger.info(f"Metadata saved successfully at {file_path}")
        except IOError as e:
            logger.error(f"Failed to save metadata to {file_path}: {e}")
            raise

    def load_metadata_from_json(self, file_path: str) -> dict:
        """
        Loads metadata from a JSON file.

        Args:
            file_path (str): Path to the metadata JSON file.

        Returns:
            dict: Loaded metadata.

        Raises:
            IOError: If the file cannot be read or parsed.
            json.JSONDecodeError: If the file does not contain valid JSON.
        """
        try:
            with open(file_path, 'r') as f:
                metadata = json.load(f)
            logger.info(f"Metadata loaded successfully from {file_path}")
            return metadata
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load metadata from {file_path}: {e}")
            raise

    def validate_metadata(self, metadata: dict) -> bool:
        """
        Validates essential fields in the provided metadata.

        Args:
            metadata (dict): The metadata dictionary to validate.

        Returns:
            bool: True if validation passes, False otherwise.
        """
        required_fields = ["version", "creator_id", "file_hash", "total_segments", "segments"]
        missing_fields = [field for field in required_fields if field not in metadata.get("file_header", {})]

        if missing_fields:
            logger.warning(f"Metadata validation failed. Missing fields: {missing_fields}")
            return False

        logger.debug("Metadata validation passed.")
        return True

    def update_access_log(self, metadata: dict, node_id: str):
        """
        Updates access context within metadata for replication and access scaling.

        Args:
            metadata (dict): The metadata dictionary to update.
            node_id (str): Unique identifier of the accessing node.
        """
        access_context = metadata.setdefault("access_context", {
            "access_count": 0,
            "last_accessed": None,
            "node_access_history": []
        })

        access_context["access_count"] += 1
        access_context["last_accessed"] = datetime.utcnow().isoformat()
        access_context["node_access_history"].append(node_id)

        logger.debug(f"Access log updated for node {node_id}. Total access count: {access_context['access_count']}")
