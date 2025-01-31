from typing import Dict, List, Optional

from src.utils.timestamp_utils import get_current_protobuf_timestamp
from src.crypto.hash_utils import hypha_hash
from src.logger.secure_logger import secure_logger
from src.dot_seigr.lineage.lineage import Lineage
from src.dot_seigr.lineage.lineage_integrity import LineageIntegrity
from src.seigr_protocol.compiled.access_control_pb2 import AccessContext
from src.seigr_protocol.compiled.coordinate_pb2 import CoordinateIndex
from src.seigr_protocol.compiled.file_metadata_pb2 import FileMetadata
from src.seigr_protocol.compiled.segment_metadata_pb2 import SegmentMetadata
from src.seigr_protocol.compiled.lineage_pb2 import TemporalLayer
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorSeverity  # ✅ Correct import
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity


class MetadataManager:
    """
    Manages segment, file, and temporal layer metadata, along with lineage tracking and integrity validation.
    """

    def __init__(self, creator_id: str, version: str = "1.0"):
        """
        Initializes the MetadataManager for managing segment, file, and temporal layer metadata.

        Args:
            creator_id (str): Unique identifier for the creator of the file or segments.
            version (str): Metadata version identifier.
        """
        self.creator_id = creator_id
        self.version = version
        self.lineage = Lineage(creator_id)
        self.integrity_checker = LineageIntegrity()

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="MetadataManager",
            message=f"✅ MetadataManager initialized for {creator_id}.",
        )

    def generate_segment_metadata(
        self,
        index: int,
        segment_hash: str,
        primary_link: Optional[str] = None,
        secondary_links: Optional[List[str]] = None,
        coordinate_index: Optional[Dict[str, int]] = None,
    ) -> SegmentMetadata:
        """
        Generates metadata for an individual segment, including lineage tracking.

        Args:
            index (int): Position of the segment in the original file sequence.
            segment_hash (str): Unique hash identifier of the segment.
            primary_link (str, optional): Primary link hash.
            secondary_links (list, optional): List of secondary link hashes.
            coordinate_index (dict, optional): Coordinates for segment placement.

        Returns:
            SegmentMetadata: Metadata object for the segment.
        """
        coord_index = (
            CoordinateIndex(
                x=coordinate_index.get("x", 0),
                y=coordinate_index.get("y", 0),
                z=coordinate_index.get("z", 0),
            )
            if coordinate_index
            else CoordinateIndex()
        )

        self._add_lineage_entry(
            action="create_segment",
            metadata={"segment_hash": segment_hash},
        )

        metadata = SegmentMetadata(
            version=self.version,
            creator_id=self.creator_id,
            segment_index=index,
            segment_hash=segment_hash,
            timestamp=get_current_protobuf_timestamp(),
            primary_link=primary_link or "",
        )
        metadata.secondary_links.extend(secondary_links or [])
        metadata.coordinate_index.CopyFrom(coord_index)

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="MetadataManager",
            message=f"✅ Generated metadata for segment {index}.",
        )
        return metadata

    def generate_file_metadata(
        self,
        original_filename: str,
        original_extension: str,
        segments: List[SegmentMetadata],
    ) -> FileMetadata:
        """
        Generates metadata for a complete Seigr file, with lineage tracking.

        Args:
            original_filename (str): Original name of the file.
            original_extension (str): Original file extension.
            segments (list): List of SegmentMetadata objects.

        Returns:
            FileMetadata: Metadata object for the complete file.
        """
        combined_segment_hashes = "".join([segment.segment_hash for segment in segments])
        file_hash = hypha_hash(combined_segment_hashes.encode())

        self._add_lineage_entry(
            action="create_file",
            metadata={"file_hash": file_hash},
        )

        file_metadata = FileMetadata(
            version=self.version,
            creator_id=self.creator_id,
            original_filename=original_filename,
            original_extension=original_extension,
            file_hash=file_hash,
            creation_timestamp=get_current_protobuf_timestamp(),
            total_segments=len(segments),
        )
        file_metadata.segments.extend(segments)

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="MetadataManager",
            message=f"✅ Generated file metadata with hash: {file_hash}.",
        )
        return file_metadata

    def create_temporal_layer(self, segments: List[SegmentMetadata]) -> TemporalLayer:
        """
        Creates a new temporal layer based on the provided segments, including lineage.

        Args:
            segments (list): List of SegmentMetadata for this layer snapshot.

        Returns:
            TemporalLayer: Populated TemporalLayer message.
        """
        combined_hash = hypha_hash("".join([seg.segment_hash for seg in segments]).encode())

        self._add_lineage_entry(
            action="create_temporal_layer",
            metadata={"layer_hash": combined_hash},
        )

        temporal_layer = TemporalLayer(
            timestamp=get_current_protobuf_timestamp(), layer_hash=combined_hash
        )
        temporal_layer.segments.extend(segments)

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="MetadataManager",
            message=f"✅ Created temporal layer with hash {combined_hash}.",
        )
        return temporal_layer

    def update_access_log(self, metadata: FileMetadata, hyphen_id: str):
        """
        Updates the access log in the metadata, tracking access counts and hyphen history.

        Args:
            metadata (FileMetadata): The metadata object to update.
            hyphen_id (str): Identifier of the accessing hyphen (e.g., node).
        """
        if not metadata.HasField("access_context"):
            metadata.access_context.CopyFrom(
                AccessContext(access_count=0, hyphen_access_history=[])
            )

        access_context = metadata.access_context
        access_context.access_count += 1
        access_context.last_accessed.CopyFrom(get_current_protobuf_timestamp())
        access_context.hyphen_access_history.append(hyphen_id)

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="MetadataManager",
            message=f"✅ Access log updated for hyphen {hyphen_id}. Total access count: {access_context.access_count}.",
        )

    def validate_lineage(self) -> bool:
        """
        Validates the integrity of the lineage, ensuring that all entries are unmodified.

        Returns:
            bool: True if lineage integrity is maintained, False otherwise.
        """
        reference_hash = self.lineage.current_hash
        is_valid = self.integrity_checker.verify(self.lineage.entries, reference_hash)

        if is_valid:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="MetadataManager",
                message="✅ Lineage integrity validated successfully.",
            )
        else:
            secure_logger.log_audit_event(
                severity=ErrorSeverity.ERROR_SEVERITY_CRITICAL,
                category="MetadataManager",
                message="❌ Lineage integrity validation failed.",
            )

        return is_valid

    def _add_lineage_entry(self, action: str, metadata: Dict[str, str]):
        """
        Adds an entry to the lineage for tracking key actions on metadata.

        Args:
            action (str): The action performed (e.g., "create_segment").
            metadata (dict): Metadata details related to the action.
        """
        self.lineage.add_entry(action=action, contributor_id=self.creator_id, metadata=metadata)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="MetadataManager",
            message=f"✅ Lineage entry added: {action}.",
        )
