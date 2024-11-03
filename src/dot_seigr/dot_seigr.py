# src/dot_seigr/dot_seigr.py

import logging
from src.crypto.hypha_crypt import encode_to_senary, generate_hash
from .seigr_file import save_seigr
from .seigr_constants import SEIGR_SIZE, HEADER_SIZE, MIN_REPLICATION
from src.dot_seigr.seed_dot_seigr import SeedDotSeigr  # Correctly import SeedDotSeigr

# Setup logging
logger = logging.getLogger(__name__)

class DotSeigr:
    def __init__(self, data: bytes, creator_id: str, previous_hash: str = None, file_type: str = "binary"):
        """
        Initializes a DotSeigr instance for creating and managing .seigr files.

        Args:
            data (bytes): Binary data to be segmented and saved.
            creator_id (str): Unique ID for the creator.
            previous_hash (str): Hash of the previous .seigr file (optional).
            file_type (str): Type of the file (default is "binary").
        """
        self.data = data
        self.creator_id = creator_id
        self.previous_hash = previous_hash or ""
        self.file_type = file_type
        self.version = "1.0"
        self.hash = ""
        self.replication_count = MIN_REPLICATION

    def create_segmented_seigr_files(self, directory: str, seed: SeedDotSeigr):
        """
        Segments data, creates .seigr files, and saves them with metadata.

        Args:
            directory (str): Directory to save the .seigr files.
            seed (SeedDotSeigr): Seed manager for cluster association.

        Returns:
            SeedDotSeigr: Updated seed with added .seigr files.
        """
        segment_size = SEIGR_SIZE - HEADER_SIZE  # Calculate usable segment size for each .seigr file
        total_parts = (len(self.data) + segment_size - 1) // segment_size  # Calculate number of parts

        for part_index in range(total_parts):
            # Extract segment
            start = part_index * segment_size
            end = start + segment_size
            segment_data = self.data[start:end]

            # Encode the segment data
            encoded_data = encode_to_senary(segment_data)

            # Generate hash for integrity and identification
            segment_hash = generate_hash(encoded_data)

            # Create .seigr metadata
            seigr_content = {
                "header": {
                    "version": self.version,
                    "file_type": self.file_type,
                    "creator_id": self.creator_id,
                    "part_index": part_index,
                    "total_parts": total_parts,
                    "previous_hash": self.previous_hash,
                    "hash": segment_hash,
                    "replication_count": self.replication_count
                },
                "data": encoded_data
            }

            # Save the segment as a .seigr file
            file_path = save_seigr(seigr_content, directory, seed)
            logger.info(f"Saved .seigr file part {part_index + 1}/{total_parts} at {file_path}")

            # Update the previous hash for linking
            self.previous_hash = segment_hash

        logger.info("All segments created and saved successfully.")
        return seed
