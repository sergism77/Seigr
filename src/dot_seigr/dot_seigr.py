# src/dot_seigr/dot_seigr.py

import os
import zlib
import json
import logging
from datetime import datetime, timezone
from src.crypto.hypha_crypt import encode_to_senary, decode_from_senary, generate_hash
from src.dot_seigr.seed_dot_seigr import SeedDotSeigr

# Constants
SEIGR_SIZE = 539 * 1024  # Each .seigr file is 539 KB
HEADER_SIZE = 128        # Reserved space in bytes for the header
MIN_REPLICATION = 6      # Minimum replication threshold for each .seigr
MAX_SEED_CLUSTER_SIZE = 20 * SEIGR_SIZE  # Seed cluster size limit

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class DotSeigr:
    def __init__(self, data: bytes, creator_id: str, previous_hash: str = None, file_type: str = "binary"):
        self.data = data
        self.creator_id = creator_id
        self.previous_hash = previous_hash or ""
        self.file_type = file_type
        self.version = "1.0"
        self.next_hash = ""
        self.senary_data = ""
        self.hash = ""
        self.replication_count = MIN_REPLICATION
        self.associated_segments = []
        self.lineage_hash = ""

    ### Core .seigr File Functions ###

    def compress_data(self) -> bytes:
        """Compresses the original data for storage efficiency."""
        try:
            compressed_data = zlib.compress(self.data)
            logger.debug("Data compressed successfully.")
            return compressed_data
        except Exception as e:
            logger.error(f"Data compression failed: {e}")
            raise

    def encode_data(self, compressed_data: bytes) -> str:
        """Encodes compressed data to senary format."""
        try:
            senary_data = encode_to_senary(compressed_data)
            logger.debug("Data encoded to senary successfully.")
            return senary_data
        except Exception as e:
            logger.error(f"Data encoding failed: {e}")
            raise

    def create_seigr(self, part_index: int = None, total_parts: int = None) -> dict:
        """Creates a .seigr file dictionary with header, encoded data, and integrity hash."""
        compressed_data = self.compress_data()
        senary_data = self.encode_data(compressed_data)

        # Ensure data fits within SEIGR_SIZE - HEADER_SIZE by truncating if needed
        if len(senary_data) > SEIGR_SIZE - HEADER_SIZE:
            senary_data = senary_data[:SEIGR_SIZE - HEADER_SIZE]

        self.senary_data = senary_data
        self.hash = generate_hash(senary_data)

        seigr_file = {
            "header": {
                "version": self.version,
                "file_type": self.file_type,
                "creator_id": self.creator_id,
                "part_index": part_index,
                "total_parts": total_parts,
                "associated_segments": self.associated_segments,
                "previous_hash": self.previous_hash,
                "next_hash": self.next_hash,
                "hash": self.hash,
                "replication_count": self.replication_count,
                "lineage_hash": self.lineage_hash
            },
            "data": self.senary_data
        }
        logger.debug(f".seigr file structure created: {seigr_file['header']}")
        return seigr_file

    def save_to_disk(self, directory: str, seed: SeedDotSeigr) -> str:
        """
        Saves the .seigr file to disk and updates the seed file.
        
        Args:
            directory (str): Directory to save the .seigr file.
            seed (SeedDotSeigr): Seed file manager to handle cluster and segment tracking.
        
        Returns:
            str: Path to the saved .seigr file.
        """
        seigr_content = self.create_seigr()
        filename = f"{self.hash}.seigr"
        file_path = os.path.join(directory, filename)

        try:
            # Save the .seigr file itself
            with open(file_path, 'w') as file:
                json.dump(seigr_content, file, indent=4)
            logger.info(f".seigr file saved as {file_path}")

            # Update the seed file with the current segment's hash
            seed.add_segment(self.hash)
            if seed.size >= MAX_SEED_CLUSTER_SIZE:
                # Save and start a new seed cluster when size limit is reached
                seed.save_to_disk(directory)
                seed = SeedDotSeigr(creator_id=self.creator_id)
                logger.debug("New SeedDotSeigr cluster initialized due to size limit.")

            seed.save_to_disk(directory)
            return file_path
        except Exception as e:
            logger.error(f"Failed to save .seigr file: {e}")
            raise

    ### Lineage Tracking ###

    def update_lineage(self, action: str, contributor_id: str = None) -> list:
        """Updates the lineage record with a new action (e.g., RE License transfer)."""
        timestamp = datetime.now(timezone.utc).isoformat()
        
        entry = {
            "action": action,
            "creator_id": self.creator_id,
            "contributor_id": contributor_id,
            "timestamp": timestamp,
            "file_hash": self.hash
        }

        lineage = self.load_lineage() if self.lineage_hash else []
        lineage.append(entry)
        self.lineage_hash = generate_hash(str(lineage))
        logger.debug(f"Lineage updated with action: {action}")
        return lineage
    
    def load_lineage(self) -> list:
        """Loads the lineage record if available."""
        lineage = []
        logger.debug("Lineage loaded successfully.")
        return lineage

    ### Verification and Integrity Checks ###

    def verify_integrity(self) -> bool:
        """Verifies the integrity of a .seigr file using its hash."""
        computed_hash = generate_hash(self.senary_data)
        is_valid = computed_hash == self.hash
        logger.info(f"Integrity check {'passed' if is_valid else 'failed'} for .seigr file.")
        return is_valid

    def decode_data(self) -> bytes:
        """Decodes and decompresses the senary-encoded data back to its original form."""
        try:
            decoded_data = decode_from_senary(self.senary_data)
            original_data = zlib.decompress(decoded_data)
            logger.debug("Data decoded and decompressed successfully.")
            return original_data
        except Exception as e:
            logger.error(f"Data decoding failed: {e}")
            raise

    ### Scalability: Adaptive Replication and Associated Segments ###

    def add_associated_segment(self, segment_hash: str):
        """Adds a hash of another segment file to the associated_segments list."""
        if segment_hash not in self.associated_segments:
            self.associated_segments.append(segment_hash)
            logger.debug(f"Associated segment {segment_hash} added.")

    def check_replication_count(self, network_replication: int):
        """Ensures the file meets minimum replication requirements, adjusting if needed."""
        if network_replication < self.replication_count:
            self.replication_count = max(self.replication_count, network_replication)
            logger.info(f"Replication count updated to {self.replication_count}.")
        else:
            logger.info(f"Replication count ({network_replication}) meets or exceeds minimum ({self.replication_count}).")
