import logging
import os
from datetime import datetime, timezone
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import (
    TextFileMetadata,
    SegmentMetadata,
)
from src.crypto.hypha_crypt import encode_to_senary, decode_from_senary
from src.crypto.hash_utils import hypha_hash

logger = logging.getLogger(__name__)


class DataInterpreter:
    """
    Processes and formats `.seigr` data for human-readable display and browser compatibility.
    Provides methods for encoding, decoding, and preparing metadata and segment data for visualization.
    """

    def __init__(self, creator_id: str):
        """
        Initializes the DataInterpreter with a specific creator ID for traceability.

        Args:
            creator_id (str): Unique identifier of the creator.
        """
        self.creator_id = creator_id
        logger.info(f"DataInterpreter initialized for creator {creator_id}")

    def encode_text_to_senary(self, text: str) -> str:
        """
        Encodes plain text to senary format for `.seigr` storage.

        Args:
            text (str): The text content to encode.

        Returns:
            str: The senary-encoded text content.
        """
        if not text:
            logger.warning("Empty text provided for encoding.")
            return ""
        encoded_data = encode_to_senary(text.encode("utf-8"))
        logger.debug("Text encoded to senary format.")
        return encoded_data

    def decode_senary_to_text(self, senary_data: bytes) -> str:
        """
        Decodes senary-encoded data back into human-readable text.

        Args:
            senary_data (bytes): The senary-encoded data to decode.

        Returns:
            str: The decoded text content.
        """
        if not senary_data:
            logger.warning("Empty senary data provided for decoding.")
            return ""
        decoded_bytes = decode_from_senary(senary_data)
        decoded_text = decoded_bytes.decode("utf-8")
        logger.debug("Senary data decoded to text format.")
        return decoded_text

    def generate_text_metadata(
        self, file_name: str, version: str = "1.0"
    ) -> TextFileMetadata:
        """
        Generates metadata for a text `.seigr` file, including creator and version information.

        Args:
            file_name (str): The file name for the `.seigr` file.
            version (str): Version of the file format (default is "1.0").

        Returns:
            TextFileMetadata: Metadata containing basic information about the text file.
        """
        if not file_name:
            logger.error("No file name provided for metadata generation.")
            return None
        metadata = TextFileMetadata(
            creator_id=self.creator_id,
            file_name=file_name,
            created_at=datetime.now(timezone.utc).isoformat(),
            version=version,
        )
        metadata.file_hash = hypha_hash(file_name.encode())
        logger.debug("Metadata generated for text file.")
        return metadata

    def save_metadata(
        self, metadata: TextFileMetadata, segments: list[SegmentMetadata], base_dir: str
    ) -> str:
        """
        Saves metadata for a `.seigr` file, linking it with segment paths.

        Args:
            metadata (TextFileMetadata): Metadata for the `.seigr` file.
            segments (list[SegmentMetadata]): List of segment metadata.
            base_dir (str): Directory to save metadata.

        Returns:
            str: Path to the saved metadata file.
        """
        if not os.path.isdir(base_dir):
            logger.error(f"Invalid directory: {base_dir}")
            raise FileNotFoundError(f"Base directory not found: {base_dir}")

        metadata_path = os.path.join(base_dir, f"{metadata.file_name}.metadata")
        metadata.segment_count = len(segments)
        metadata.file_hash = hypha_hash(
            "".join(seg.segment_hash for seg in segments).encode()
        )

        try:
            with open(metadata_path, "wb") as f:
                f.write(metadata.SerializeToString())
            logger.info(f"Metadata saved at {metadata_path}")
        except IOError as e:
            logger.error(f"Failed to save metadata: {e}")
            raise

        return metadata_path

    def parse_segment_metadata(
        self, segment_data: bytes, segment_index: int
    ) -> SegmentMetadata:
        """
        Generates metadata for an individual segment, storing the hash and creator ID.

        Args:
            segment_data (bytes): Data of the segment to create metadata for.
            segment_index (int): Index of the segment in the sequence.

        Returns:
            SegmentMetadata: Metadata object for the segment.
        """
        if not segment_data:
            logger.warning(f"Empty segment data at index {segment_index}")
            return None
        segment_hash = hypha_hash(segment_data)
        metadata = SegmentMetadata(
            creator_id=self.creator_id,
            segment_index=segment_index,
            segment_hash=segment_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        logger.debug(f"Segment metadata generated for index {segment_index}")
        return metadata

    def prepare_segment_for_display(self, segment_data: bytes) -> dict:
        """
        Decodes segment data and structures it for display in a JSON-compatible format.

        Args:
            segment_data (bytes): Encoded segment data.

        Returns:
            dict: JSON-friendly structure of decoded segment data.
        """
        if not segment_data:
            logger.warning("Empty segment data provided.")
            return {"error": "No data provided"}
        try:
            decoded_text = self.decode_senary_to_text(segment_data)
            return {"decoded_text": decoded_text, "senary_values": list(decoded_text)}
        except Exception as e:
            logger.error(f"Failed to prepare segment for display: {e}")
            return {"error": str(e)}

    def decode_segments(self, segment_files: list[str], base_dir: str) -> list:
        """
        Decodes data from `.seigr` segments into a readable format, structured for browser display.

        Args:
            segment_files (list[str]): Paths to each segment file.
            base_dir (str): Directory where segment files are located.

        Returns:
            list: Each segment's decoded content and display-ready data.
        """
        decoded_segments = []
        for segment_file in segment_files:
            segment_path = os.path.join(base_dir, segment_file)
            if not os.path.isfile(segment_path):
                logger.warning(f"Segment file not found: {segment_file}")
                continue
            try:
                with open(segment_path, "rb") as f:
                    segment_data = f.read()
                    segment_display_data = self.prepare_segment_for_display(
                        segment_data
                    )
                    decoded_segments.append(segment_display_data)
            except IOError as e:
                logger.error(f"Failed to read segment {segment_file}: {e}")
                continue

        logger.info(f"Decoded {len(decoded_segments)} segments for display.")
        return decoded_segments
