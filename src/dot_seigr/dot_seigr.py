import logging
import json
from src.crypto.hypha_crypt import HyphaCrypt
from .seigr_file import SeigrFile
from .seigr_constants import SEIGR_SIZE, HEADER_SIZE, MIN_REPLICATION
from src.dot_seigr.seed_dot_seigr import SeedDotSeigr  # Correctly import SeedDotSeigr

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
        self.primary_path = None  # Primary path link for adaptive access
        self.secondary_paths = []  # Initialize empty secondary paths

    def create_segmented_seigr_files(self, directory: str, seed: SeedDotSeigr):
        """
        Segments data, creates .seigr files, and saves them with multidimensional metadata.

        Args:
            directory (str): Directory to save the .seigr files.
            seed (SeedDotSeigr): Seed manager for cluster association.

        Returns:
            SeedDotSeigr: Updated seed with added .seigr files.
        """
        segment_size = SEIGR_SIZE - HEADER_SIZE  # Calculate usable segment size for each .seigr file
        total_parts = (len(self.data) + segment_size - 1) // segment_size  # Calculate number of parts
        last_hash = None  # Track hash for the multidimensional links

        for part_index in range(total_parts):
            # Extract and encode segment data in senary format
            start = part_index * segment_size
            end = start + segment_size
            segment_data = self.data[start:end]

            # Initialize HyphaCrypt for cryptographic handling of the segment
            hypha_crypt = HyphaCrypt(data=segment_data, segment_id=f"{self.creator_id}_{part_index}")
            encoded_data = hypha_crypt.encode_to_senary(segment_data)

            # Generate primary hash for this segment
            primary_hash = hypha_crypt.compute_primary_hash()

            # Initialize SeigrFile for this segment with multidimensional hash linking
            seigr_file = SeigrFile(
                data=encoded_data,
                creator_id=self.creator_id,
                index=part_index,
                file_type=self.file_type
            )

            # Set up primary link from the previous segment's hash, forming a chain
            if last_hash:
                self.primary_path = last_hash
            seigr_file.set_links(primary_link=self.primary_path, secondary_links=self.secondary_paths)

            # Add a temporal layer to store the initial state
            seigr_file.add_temporal_layer()

            # Save the .seigr segment to disk
            file_path = seigr_file.save_to_disk(directory)
            logger.info(f"Saved .seigr file part {part_index + 1}/{total_parts} at {file_path}")

            # Prepare multidimensional secondary links for alternative access paths
            secondary_link = hypha_crypt.compute_layered_hashes()
            self.secondary_paths.append(secondary_link)

            # Update last_hash to the primary hash of this segment
            last_hash = primary_hash

            # Add the segment to the seed for clustering
            seed.add_file(file_path)

            # Save hash tree and secondary paths to a separate file for traceability
            hash_tree_path = f"{directory}/{self.creator_id}_{part_index}_hash_tree.json"
            with open(hash_tree_path, 'w') as f:
                json.dump(secondary_link, f, indent=4)
            logger.debug(f"Hash tree for segment {part_index} saved to {hash_tree_path}")

        logger.info("All segments created and saved successfully.")
        return seed
