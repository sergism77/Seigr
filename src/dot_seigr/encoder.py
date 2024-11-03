# src/dot_seigr/encoder.py

import os
import zlib
import json
import logging
from src.crypto.hypha_crypt import encode_to_senary, generate_hash
from src.dot_seigr.dot_seigr import DotSeigr
from src.dot_seigr.seed_dot_seigr import SeedDotSeigr

# Constants
SEIGR_SIZE = 539 * 1024  # Each .seigr file is 539 KB
HEADER_SIZE = 128        # Reserved space in bytes for the header
MAX_SEED_SIZE = 20 * SEIGR_SIZE  # Maximum size for each seed cluster in bytes
BLANK_SPACE_RATIO = 0.1  # Reserve 10% of each .seigr file for future updates

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeigrEncoder:
    def __init__(self, data: bytes, creator_id: str, base_dir: str):
        self.data = data
        self.creator_id = creator_id
        self.base_dir = base_dir
        self.segments = []  # Track each generated .seigr file hash
        self.blank_space = int((SEIGR_SIZE - HEADER_SIZE) * BLANK_SPACE_RATIO)  # Blank space per .seigr file

    def compress_and_encode(self) -> str:
        """Compresses and encodes the data to senary format for .seigr files."""
        try:
            compressed_data = zlib.compress(self.data)
            senary_data = encode_to_senary(compressed_data)
            logger.debug("Data compressed and senary encoded successfully.")
            return senary_data
        except Exception as e:
            logger.error(f"Compression and encoding failed: {e}")
            raise

    def segment_data(self, senary_data: str):
        """
        Splits senary data into segments that fit within a .seigr file.
        Each segment is padded with blank space for potential future updates.
        """
        segment_size = SEIGR_SIZE - HEADER_SIZE - self.blank_space
        segments = [senary_data[i:i + segment_size].ljust(segment_size) for i in range(0, len(senary_data), segment_size)]
        logger.debug(f"Data segmented into {len(segments)} parts.")
        return segments

    def encode_to_seigr_files(self):
        """Encodes data into .seigr files, and organizes them into clusters within SeedDotSeigr."""
        # Compress and encode data to senary
        senary_data = self.compress_and_encode()
        
        # Segment data for individual .seigr files
        segments = self.segment_data(senary_data)

        # Initialize or load the primary SeedDotSeigr file
        seed_file_path = os.path.join(self.base_dir, f"{self.creator_id}_seed.seigr")
        if os.path.exists(seed_file_path):
            seed_file = SeedDotSeigr.load_from_disk(seed_file_path)
            logger.debug("Loaded existing SeedDotSeigr file.")
        else:
            seed_file = SeedDotSeigr(creator_id=self.creator_id)
            logger.debug("Initialized a new SeedDotSeigr file.")

        current_seed_size = 0

        # Generate .seigr files and update the SeedDotSeigr
        for index, segment in enumerate(segments):
            try:
                dot_seigr = DotSeigr(data=segment.encode('utf-8'), creator_id=self.creator_id)
                seigr_content = dot_seigr.create_seigr(part_index=index, total_parts=len(segments))
                file_path = dot_seigr.save_to_disk(self.base_dir)
                self.segments.append(dot_seigr.hash)

                # Update seed with new segment hash and associated segments
                seed_file.add_segment(dot_seigr.hash)
                current_seed_size += SEIGR_SIZE
                logger.debug(f"Added .seigr file with hash {dot_seigr.hash} to SeedDotSeigr.")

                # Check if we need a new cluster for seed file
                if current_seed_size >= MAX_SEED_SIZE:
                    # Save current seed file and start a new cluster
                    seed_file.save_to_disk(self.base_dir)
                    seed_file = SeedDotSeigr(creator_id=self.creator_id)
                    seed_file.add_segment(dot_seigr.hash)
                    current_seed_size = SEIGR_SIZE  # Reset with first segment of new seed
                    logger.debug("Started a new SeedDotSeigr cluster due to size limit.")
            except Exception as e:
                logger.error(f"Failed to encode or save .seigr file segment {index}: {e}")
                raise

        # Save the final seed file to disk
        try:
            seed_file.save_to_disk(self.base_dir)
            logger.info(f"Encoding complete. Generated {len(segments)} .seigr files and updated SeedDotSeigr.")
        except Exception as e:
            logger.error(f"Failed to save the final SeedDotSeigr file: {e}")
            raise
