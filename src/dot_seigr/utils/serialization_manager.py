# src/dot_seigr/utils/serialization_manager.py

import logging

from src.dot_seigr.capsule.seigr_serializer import CapsuleSerializer
from src.seigr_protocol.compiled.file_metadata_pb2 import FileMetadata, SegmentMetadata

logger = logging.getLogger(__name__)

# Create an instance of CapsuleSerializer for reuse
_capsule_serializer = CapsuleSerializer()


def save_capsule(capsule_data, base_dir: str, filename: str) -> str:
    """
    Wrapper for CapsuleSerializer.save_capsule.

    Args:
        capsule_data (FileMetadata or SegmentMetadata): Data to serialize.
        base_dir (str): Directory for saving.
        filename (str): Filename for saved capsule.

    Returns:
        str: Path to the saved capsule file.
    """
    return _capsule_serializer.save_capsule(capsule_data, base_dir, filename)


def load_capsule(file_path: str, capsule_type) -> FileMetadata:
    """
    Wrapper for CapsuleSerializer.load_capsule.

    Args:
        file_path (str): Path to capsule file.
        capsule_type: Type (e.g., FileMetadata or SegmentMetadata) for deserialization.

    Returns:
        FileMetadata: Loaded capsule data.
    """
    return _capsule_serializer.load_capsule(file_path, capsule_type)


def save_segment_metadata(segment_metadata: SegmentMetadata, base_dir: str) -> str:
    """
    Wrapper for CapsuleSerializer.save_segment_metadata.

    Args:
        segment_metadata (SegmentMetadata): Segment metadata to save.
        base_dir (str): Directory to save metadata file.

    Returns:
        str: Path to saved metadata file.
    """
    return _capsule_serializer.save_segment_metadata(segment_metadata, base_dir)


def load_segment_metadata(file_path: str) -> SegmentMetadata:
    """
    Wrapper for CapsuleSerializer.load_segment_metadata.

    Args:
        file_path (str): Path to segment metadata file.

    Returns:
        SegmentMetadata: Loaded segment metadata.
    """
    return _capsule_serializer.load_segment_metadata(file_path)


def verify_file_integrity(file_metadata: FileMetadata, base_dir: str) -> bool:
    """
    Wrapper for CapsuleSerializer.verify_file_integrity.

    Args:
        file_metadata (FileMetadata): Metadata to verify.
        base_dir (str): Directory of segments.

    Returns:
        bool: True if all segments pass integrity check, False otherwise.
    """
    return _capsule_serializer.verify_file_integrity(file_metadata, base_dir)


def verify_capsule_integrity(capsule_data: FileMetadata, expected_hash: str) -> bool:
    """
    Wrapper for CapsuleSerializer.verify_capsule_integrity.

    Args:
        capsule_data (FileMetadata or SegmentMetadata): Capsule data to verify.
        expected_hash (str): Expected hash for verification.

    Returns:
        bool: True if integrity check passes, False otherwise.
    """
    return _capsule_serializer.verify_capsule_integrity(capsule_data, expected_hash)
