import logging
from datetime import datetime, timezone
from src.crypto.hash_utils import hypha_hash
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import (
    FileMetadata, SegmentMetadata, CoordinateIndex, AccessContext, TemporalLayer
)


logger = logging.getLogger(__name__)

class MetadataManager:
    def __init__(self, creator_id: str, version: str = "1.0"):
        self.creator_id = creator_id
        self.version = version

    def generate_segment_metadata(self, index: int, segment_hash: str, primary_link: str = None,
                                  secondary_links: list = None, coordinate_index: dict = None) -> SegmentMetadata:
        timestamp = datetime.now(timezone.utc).isoformat()
        coord_index = CoordinateIndex(
            x=coordinate_index.get("x", 0),
            y=coordinate_index.get("y", 0),
            z=coordinate_index.get("z", 0)
        ) if coordinate_index else CoordinateIndex()

        metadata = SegmentMetadata(
            version=self.version,
            creator_id=self.creator_id,
            segment_index=index,
            segment_hash=segment_hash,
            timestamp=timestamp,
            primary_link=primary_link or ""
        )
        metadata.secondary_links.extend(secondary_links or [])
        metadata.coordinate_index.CopyFrom(coord_index)

        logger.debug(f"Generated metadata for segment {index}: {metadata}")
        return metadata

    def generate_file_metadata(self, original_filename: str, original_extension: str, segments: list) -> FileMetadata:
        creation_timestamp = datetime.now(timezone.utc).isoformat()
        combined_segment_hashes = "".join([segment.segment_hash for segment in segments])
        file_hash = hypha_hash(combined_segment_hashes.encode())

        file_metadata = FileMetadata(
            version=self.version,
            creator_id=self.creator_id,
            original_filename=original_filename,
            original_extension=original_extension,
            file_hash=file_hash,
            creation_timestamp=creation_timestamp,
            total_segments=len(segments)
        )
        file_metadata.segments.extend(segments)

        logger.info(f"Generated file metadata with hash: {file_hash}")
        return file_metadata

    def create_temporal_layer(self, segments: list) -> TemporalLayer:
        """
        Creates a new temporal layer based on current segments.

        Args:
            segments (list): List of SegmentMetadata for this layer snapshot.

        Returns:
            TemporalLayer: Populated TemporalLayer message.
        """
        layer_timestamp = datetime.now(timezone.utc).isoformat()
        combined_hash = hypha_hash("".join([seg.segment_hash for seg in segments]).encode())
        temporal_layer = TemporalLayer(
            timestamp=layer_timestamp,
            layer_hash=combined_hash
        )
        temporal_layer.segments.extend(segments)
        
        logger.info(f"Created temporal layer at {layer_timestamp} with hash {combined_hash}")
        return temporal_layer

    def save_metadata(self, metadata: FileMetadata, file_path: str):
        try:
            with open(file_path, 'wb') as f:
                f.write(metadata.SerializeToString())
            logger.info(f"Metadata saved successfully at {file_path}")
        except IOError as e:
            logger.error(f"Failed to save metadata to {file_path}: {e}")
            raise

    def load_metadata(self, file_path: str) -> FileMetadata:
        metadata = FileMetadata()
        try:
            with open(file_path, 'rb') as f:
                metadata.ParseFromString(f.read())
            logger.info(f"Metadata loaded successfully from {file_path}")
            return metadata
        except (IOError, ValueError) as e:
            logger.error(f"Failed to load metadata from {file_path}: {e}")
            raise

    def update_access_log(self, metadata: FileMetadata, hyphen_id: str):
        if not metadata.HasField("access_context"):
            metadata.access_context.CopyFrom(AccessContext(access_count=0, last_accessed="", hyphen_access_history=[]))

        access_context = metadata.access_context
        access_context.access_count += 1
        access_context.last_accessed = datetime.now(timezone.utc).isoformat()
        access_context.hyphen_access_history.append(hyphen_id)
        
        logger.debug(f"Access log updated for hyphen {hyphen_id}. Total access count: {access_context.access_count}")
