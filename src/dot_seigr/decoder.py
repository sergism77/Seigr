# src/dot_seigr/decoder.py

import os
import json
import zlib
import logging
from src.crypto.hypha_crypt import decode_from_senary, generate_hash
from src.dot_seigr.dot_seigr import DotSeigr
from src.dot_seigr.seed_dot_seigr import SeedDotSeigr

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeigrDecoder:
    def __init__(self, seed_files: list, base_dir: str):
        """
        Initializes the decoder with a list of SeedDotSeigr files and the base directory for segments.
        
        Args:
            seed_files (list): List of paths to SeedDotSeigr files.
            base_dir (str): Directory containing .seigr files.
        """
        self.seed_files = seed_files
        self.base_dir = base_dir
        self.segment_hashes = []  # Combined list of all segment hashes across seed files

    def load_seed_files(self):
        """Loads all SeedDotSeigr files and aggregates segment hashes."""
        for seed_file_path in self.seed_files:
            try:
                seed_file = SeedDotSeigr.load_from_disk(seed_file_path)
                self.segment_hashes.extend(seed_file.segment_hashes)
                logger.info(f"Loaded SeedDotSeigr with {len(seed_file.segment_hashes)} segments from {seed_file_path}.")
            except Exception as e:
                logger.error(f"Failed to load SeedDotSeigr file {seed_file_path}: {e}")
                raise

    def retrieve_and_verify_segments(self) -> list:
        """
        Retrieves and verifies the integrity of each .seigr file listed in all SeedDotSeigr files.
        
        Returns:
            list: A list of verified senary-encoded data segments.
        """
        segments = []
        missing_segments = []

        for segment_hash in self.segment_hashes:
            file_path = os.path.join(self.base_dir, f"{segment_hash}.seigr")
            try:
                with open(file_path, 'r') as file:
                    seigr_content = json.load(file)

                dot_seigr = DotSeigr(
                    data=seigr_content["data"].encode('utf-8'),
                    creator_id=seigr_content["header"]["creator_id"],
                    previous_hash=seigr_content["header"]["previous_hash"],
                    file_type=seigr_content["header"]["file_type"]
                )
                dot_seigr.hash = seigr_content["header"]["hash"]  # Set hash directly for verification

                # Verify integrity
                if dot_seigr.verify_integrity():
                    segments.append(dot_seigr.senary_data)
                    logger.debug(f"Verified .seigr file: {segment_hash}")
                else:
                    logger.error(f"Integrity check failed for .seigr file: {segment_hash}")
                    raise ValueError(f"Integrity check failed for .seigr file: {segment_hash}")

            except FileNotFoundError:
                missing_segments.append(segment_hash)
                logger.warning(f"Segment {segment_hash} missing in {file_path}.")
            except Exception as e:
                logger.error(f"Failed to retrieve or verify .seigr file {segment_hash}: {e}")
                raise

        if missing_segments:
            logger.error(f"Missing segments: {missing_segments}")
            raise FileNotFoundError(f"Missing segments: {missing_segments}")

        return segments

    def decode_and_reassemble(self, segments: list) -> bytes:
        """
        Decodes and decompresses senary-encoded segments to reconstruct the original data.
        
        Args:
            segments (list): List of senary-encoded data segments.

        Returns:
            bytes: The reconstructed original data.
        """
        try:
            # Concatenate all segments into a single senary string
            senary_data = ''.join(segments)
            decoded_data = decode_from_senary(senary_data)
            original_data = zlib.decompress(decoded_data)
            logger.info("Data successfully decoded and decompressed.")
            return original_data
        except Exception as e:
            logger.error(f"Failed to decode and reassemble data: {e}")
            raise

    def decode(self) -> bytes:
        """
        Main decoding function to load seed files, retrieve segments, and reassemble the original data.
        
        Returns:
            bytes: The fully reconstructed original data.
        """
        # Load all seed files
        self.load_seed_files()
        
        # Retrieve and verify segments
        segments = self.retrieve_and_verify_segments()
        
        # Decode and reassemble original data
        original_data = self.decode_and_reassemble(segments)
        logger.info("Decoding process completed successfully.")
        return original_data
