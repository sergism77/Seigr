# interpreter/parser.py

import logging
import os
from datetime import datetime, timezone
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import TextFileMetadata, SegmentMetadata
from src.crypto.hypha_crypt import encode_to_senary, decode_from_senary
from src.crypto.hash_utils import hypha_hash

logger = logging.getLogger(__name__)

class SenaryParser:
    """
    Parser for senary content within `.seigr` capsules. 
    Provides methods to encode, decode, and manage text and segment data in senary format.
    """

    def __init__(self, creator_id: str):
        """
        Initializes the SenaryParser with a specific creator ID for traceability.

        Args:
            creator_id (str): Unique ID of the creator for this instance.
        """
        self.creator_id = creator_id
        logger.info(f"SenaryParser initialized for creator {creator_id}")

    def encode_text_to_senary(self, text: str) -> str:
        """
        Encodes plain text to senary format for `.seigr` storage.

        Args:
            text (str): The text content to encode.

        Returns:
            str: The senary-encoded text content.
        """
        encoded_data = encode_to_senary(text.encode("utf-8"))
        logger.debug(f"Encoded text to senary format for creator {self.creator_id}")
        return encoded_data

    def decode_senary_to_text(self, senary_data: bytes) -> str:
        """
        Decodes senary-encoded data back into human-readable text.

        Args:
            senary_data (bytes): The senary-encoded data to decode.

        Returns:
            str: The decoded text content.
        """
        decoded_bytes = decode_from_senary(senary_data)
        decoded_text = decoded_bytes.decode("utf-8")
        logger.debug(f"Decoded senary data to text format for creator {self.creator_id}")
        return decoded_text

    def generate_text_metadata(self, file_name: str, version: str = "1.0") -> TextFileMetadata:
        """
        Generates metadata for a text `.seigr` file, storing the creator and version information.

        Args:
            file_name (str): The file name for the `.seigr` file.
            version (str): Version of the file format (default is "1.0").

        Returns:
            TextFileMetadata: Metadata containing basic information about the text file.
        """
        metadata = TextFileMetadata(
            creator_id=self.creator_id,
            file_name=file_name,
            created_at=datetime.now(timezone.utc).isoformat(),
            version=version
        )
        metadata.file_hash = hypha_hash(file_name.encode())
        logger.debug(f"Generated metadata for text file: {file_name}")
        return metadata

    def save_metadata(self, metadata: TextFileMetadata, segments: list[SegmentMetadata], base_dir: str) -> str:
        """
        Saves metadata for a `.seigr` file, linking it with segment paths and ensuring traceability.

        Args:
            metadata (TextFileMetadata): Metadata for the `.seigr` file.
            segments (list[SegmentMetadata]): List of segment metadata.
            base_dir (str): Directory to save metadata.

        Returns:
            str: Path to the saved metadata file.
        """
        metadata_path = f"{base_dir}/{metadata.file_name}.metadata"
        metadata.segment_count = len(segments)
        metadata.file_hash = hypha_hash("".join([seg.segment_hash for seg in segments]).encode())

        with open(metadata_path, "wb") as f:
            f.write(metadata.SerializeToString())
        
        logger.info(f"Metadata saved at {metadata_path}")
        return metadata_path

    def parse_segment_metadata(self, segment_data: bytes, segment_index: int) -> SegmentMetadata:
        """
        Generates metadata for an individual segment, storing the hash and creator ID.

        Args:
            segment_data (bytes): Data of the segment to create metadata for.
            segment_index (int): Index of the segment in the sequence.

        Returns:
            SegmentMetadata: Metadata object for the segment.
        """
        segment_hash = hypha_hash(segment_data)
        metadata = SegmentMetadata(
            creator_id=self.creator_id,
            segment_index=segment_index,
            segment_hash=segment_hash,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        logger.debug(f"Generated metadata for segment {segment_index} with hash {segment_hash}")
        return metadata

    def validate_metadata(self, metadata: TextFileMetadata) -> bool:
        """
        Validates metadata by ensuring the file hash and segment counts are consistent.

        Args:
            metadata (TextFileMetadata): Metadata to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        # Recalculate the file hash for validation
        recalculated_hash = hypha_hash(metadata.file_name.encode())
        is_valid = metadata.file_hash == recalculated_hash

        if is_valid:
            logger.info(f"Metadata validation successful for {metadata.file_name}")
        else:
            logger.error(f"Metadata validation failed for {metadata.file_name}. Expected {metadata.file_hash}, got {recalculated_hash}")
        
        return is_valid

    def decode_segments(self, segment_files: list[str], base_dir: str) -> str:
        """
        Decodes data from `.seigr` segments back into a readable format.

        Args:
            segment_files (list[str]): List of file paths for each segment.
            base_dir (str): Directory where segment files are located.

        Returns:
            str: Full decoded content as a single string.
        """
        decoded_data = bytearray()

        for segment_file in segment_files:
            segment_path = os.path.join(base_dir, segment_file)
            with open(segment_path, "rb") as f:
                segment_data = f.read()
                decoded_segment = decode_from_senary(segment_data)
                decoded_data.extend(decoded_segment)
        
        decoded_content = decoded_data.decode("utf-8")
        logger.info(f"Decoded segments from {len(segment_files)} files into full content.")
        return decoded_content
