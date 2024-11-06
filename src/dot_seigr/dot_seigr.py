import os
import logging
from datetime import datetime, timezone
from src.crypto.hypha_crypt import HyphaCrypt
from src.dot_seigr.seigr_file import SeigrFile
from src.dot_seigr.seigr_constants import SEIGR_SIZE, HEADER_SIZE, MIN_REPLICATION
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SeedDotSeigr as SeedDotSeigrProto
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

    def create_segmented_seigr_files(self, directory: str, seed: SeedDotSeigrProto) -> SeedDotSeigrProto:
        """
        Segments data, creates .seigr files, and saves them with protocol-compliant Protobuf metadata.

        Args:
            directory (str): Directory to save the .seigr files.
            seed (SeedDotSeigrProto): Seed protobuf structure for managing the cluster.

        Returns:
            SeedDotSeigrProto: Updated seed with added .seigr files.
        """
        segment_size = SEIGR_SIZE - HEADER_SIZE  # Calculate usable segment size
        total_parts = (len(self.data) + segment_size - 1) // segment_size  # Total number of segments
        last_primary_hash = None  # Track previous primary hash for chaining

        # Ensure directory exists
        os.makedirs(directory, exist_ok=True)

        for part_index in range(total_parts):
            # Create and save each segment as a .seigr file
            try:
                primary_hash, file_path, secondary_link = self._create_and_save_segment(
                    directory, part_index, segment_size, last_primary_hash
                )
                
                # Update last primary hash for linking the next segment
                last_primary_hash = primary_hash

                # Add the saved file path to the SeedDotSeigrProto instance
                seed_file_metadata = seed.segments.add()
                seed_file_metadata.segment_hash = primary_hash
                seed_file_metadata.timestamp = datetime.now(timezone.utc).isoformat()

                # Log hash tree and link for traceability
                logger.debug(f"Hash tree for segment {part_index} and secondary links added.")

            except Exception as e:
                logger.error(f"Failed to create and save segment {part_index}: {e}")
                raise

        logger.info("All segments created and saved successfully.")
        return seed

    def _create_and_save_segment(self, directory: str, part_index: int, segment_size: int, last_primary_hash: str):
        """
        Creates and saves a single .seigr file segment.

        Args:
            directory (str): Directory to save the .seigr file.
            part_index (int): The segment index.
            segment_size (int): Size of each segment.
            last_primary_hash (str): Hash of the previous segment for linking.

        Returns:
            tuple: Primary hash, file path, and secondary link for the segment.
        """
        # Extract segment data and initialize encryption
        start = part_index * segment_size
        end = start + segment_size
        segment_data = self.data[start:end]

        # Initialize HyphaCrypt for segment cryptographic handling
        hypha_crypt = HyphaCrypt(data=segment_data, segment_id=f"{self.creator_id}_{part_index}")
        primary_hash = hypha_crypt.compute_primary_hash()

        # Create SeigrFile instance
        seigr_file = SeigrFile(
            data=segment_data,
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

        # Add a temporal layer for the current state of the segment
        seigr_file.add_temporal_layer()

        # Save the .seigr segment as a Protobuf file
        file_path = seigr_file.save_to_disk(directory)
        logger.info(f"Saved .seigr file part {part_index + 1} at {file_path}")

        # Generate a secondary link for adaptive retrieval paths
        secondary_link = hypha_crypt.compute_layered_hashes()
        self.link_manager.add_secondary_link(secondary_link)

        return primary_hash, file_path, secondary_link

    def save_seed_to_disk(self, seed: SeedDotSeigrProto, base_dir: str) -> str:
        """
        Saves the seed cluster as a protobuf binary file.

        Args:
            seed (SeedDotSeigrProto): The seed protobuf structure.
            base_dir (str): Directory to save the seed file.

        Returns:
            str: Path to the saved seed file.
        """
        filename = f"{self.creator_id}_seed_cluster.seigr"
        file_path = os.path.join(base_dir, filename)

        try:
            os.makedirs(base_dir, exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(seed.SerializeToString())
            logger.info(f"Seed cluster saved successfully at {file_path}")
            return file_path
        except (IOError, ValueError) as e:
            logger.error(f"Failed to save seed cluster at {file_path}: {e}")
            raise
