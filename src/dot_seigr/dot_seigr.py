import os
import logging
from src.crypto.hypha_crypt import HyphaCrypt
from src.dot_seigr.seigr_file import SeigrFile
from src.dot_seigr.seigr_constants import SEIGR_SIZE, HEADER_SIZE, MIN_REPLICATION
from src.dot_seigr.seed_dot_seigr import SeedDotSeigr
from src.dot_seigr.seigr_protocol.encoder import encode_to_senary
from src.dot_seigr.seigr_protocol.manager import LinkManager

# Setup logging
logger = logging.getLogger(__name__)

class DotSeigr:
    def __init__(self, data: bytes, creator_id: str, file_type: str = "binary"):
        """
        Initializes a DotSeigr instance for creating and managing .seigr files with multidimensional links.

        Args:
            data (bytes): Binary data to be segmented and saved.
            creator_id (str): Unique ID for the creator.
            file_type (str): Type of the file (default is "binary").
        """
        self.data = data
        self.creator_id = creator_id
        self.file_type = file_type
        self.version = "1.0"
        self.replication_count = MIN_REPLICATION
        self.link_manager = LinkManager()  # Handles primary and secondary links across segments

    def create_segmented_seigr_files(self, directory: str, seed: SeedDotSeigr):
        """
        Segments data, creates .seigr files, and saves them with protocol-compliant Protobuf metadata.

        Args:
            directory (str): Directory to save the .seigr files.
            seed (SeedDotSeigr): Seed manager for cluster association.

        Returns:
            SeedDotSeigr: Updated seed with added .seigr files.
        """
        segment_size = SEIGR_SIZE - HEADER_SIZE  # Calculate usable segment size
        total_parts = (len(self.data) + segment_size - 1) // segment_size  # Total number of segments
        last_primary_hash = None  # Track previous primary hash for chaining

        # Ensure directory exists
        os.makedirs(directory, exist_ok=True)

        for part_index in range(total_parts):
            # Extract segment and encode
            start = part_index * segment_size
            end = start + segment_size
            segment_data = self.data[start:end]
            encoded_data = encode_to_senary(segment_data)  # Encode data using protocol-based encoding

            # Initialize HyphaCrypt for segment cryptographic handling
            hypha_crypt = HyphaCrypt(data=segment_data, segment_id=f"{self.creator_id}_{part_index}")
            primary_hash = hypha_crypt.compute_primary_hash()

            # Create SeigrFile instance with encoded data and protocol metadata
            seigr_file = SeigrFile(
                data=encoded_data,
                creator_id=self.creator_id,
                index=part_index,
                file_type=self.file_type
            )

            # Set up primary and secondary links
            if last_primary_hash:
                self.link_manager.set_primary_link(last_primary_hash)
            seigr_file.set_links(
                primary_link=self.link_manager.primary_link,
                secondary_links=self.link_manager.secondary_links
            )

            # Add temporal layer for this segment’s state
            seigr_file.add_temporal_layer()

            # Save the .seigr segment as a Protobuf file
            file_path = seigr_file.save_to_disk(directory)
            logger.info(f"Saved .seigr file part {part_index + 1}/{total_parts} at {file_path}")

            # Generate a secondary link for adaptive retrieval paths
            secondary_link = hypha_crypt.compute_layered_hashes()
            self.link_manager.add_secondary_link(secondary_link)

            # Update last primary hash for linking the next segment
            last_primary_hash = primary_hash

            # Add segment path to seed manager
            seed.add_file(file_path)

            # Log hash tree and link for traceability (replace JSON with Protobuf in a future hash manager)
            logger.debug(f"Hash tree for segment {part_index} and secondary links added.")

        logger.info("All segments created and saved successfully.")
        return seed
