# src/dot_seigr/seigr_encoder.py

import os
import json
import logging
from src.crypto.hypha_crypt import HyphaCrypt
from .seigr_file import SeigrFile
from .seigr_cluster_manager import SeigrClusterManager
from .seigr_constants import SEIGR_SIZE, HEADER_SIZE, TARGET_BINARY_SEGMENT_SIZE

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeigrEncoder:
    def __init__(self, data: bytes, creator_id: str, base_dir: str, original_filename: str):
        """
        Initializes the SeigrEncoder with data, metadata, and directory information.

        Args:
            data (bytes): Binary data to encode and segment.
            creator_id (str): Unique identifier of the data creator.
            base_dir (str): Directory path for saving encoded .seigr files.
            original_filename (str): Original file name including extension.
        """
        self.data = data
        self.creator_id = creator_id
        self.base_dir = base_dir
        self.original_filename = original_filename
        self.original_extension = os.path.splitext(original_filename)[1]

    def segment_data(self):
        """
        Segments the data based on the target binary segment size.

        Returns:
            list: Segmented binary data chunks.
        """
        segment_size = TARGET_BINARY_SEGMENT_SIZE
        segments = [self.data[i:i + segment_size] for i in range(0, len(self.data), segment_size)]
        logger.debug(f"Data segmented into {len(segments)} parts with each segment up to {segment_size} bytes.")
        return segments

    def encode(self):
        # Ensure the base directory exists
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir)
            logger.info(f"Created base directory for encoded files at {self.base_dir}")

        # Initialize the cluster manager with filename and extension
        cluster_manager = SeigrClusterManager(self.creator_id, self.original_filename, self.original_extension)
        
        # Segment the data
        try:
            segments = self.segment_data()
            if not segments:
                logger.error("No segments were created. Exiting encoding process.")
                return
        except Exception as e:
            logger.error(f"Error during data segmentation: {e}")
            return

        # Process each segment, encoding and saving it as a .seigr file
        for index, segment in enumerate(segments):
            try:
                # Initialize HyphaCrypt instance for handling encryption and hashing for the segment
                hypha_crypt = HyphaCrypt(data=segment, segment_id=f"{self.creator_id}_{index}")
                
                # Encode to senary format using HyphaCrypt
                senary_data = hypha_crypt.encode_to_senary(segment)
                logger.debug(f"Segment {index + 1}/{len(segments)} encoded to senary format.")

                # Compute the primary hash for segment identification and integrity verification
                primary_hash = hypha_crypt.compute_primary_hash()
                
                # Generate a layered hash tree for multidimensional linking and traceability
                hash_tree = hypha_crypt.compute_layered_hashes()
                hash_tree_path = os.path.join(self.base_dir, f"{self.creator_id}_{index}_hash_tree.json")
                with open(hash_tree_path, 'w') as f:
                    json.dump(hash_tree, f, indent=4)
                logger.debug(f"Layered hash tree for segment {index} saved to {hash_tree_path}")

                # Initialize SeigrFile for this segment with metadata and 4D properties
                seigr_file = SeigrFile(data=senary_data, creator_id=self.creator_id, index=index, file_type="senary")

                # Save as .seigr file
                file_path = seigr_file.save_to_disk(self.base_dir)
                logger.info(f"Encoded segment {index + 1}/{len(segments)}: Saved to {file_path}")

                # Add segment to the cluster manager with index and hash
                cluster_manager.add_segment(primary_hash, index)

            except Exception as e:
                logger.error(f"Failed to encode or save segment {index + 1}: {e}")

        # Save the cluster metadata with the full filename and extension
        try:
            cluster_manager.save_cluster(self.base_dir)
            logger.info("Encoding process completed successfully.")
        except Exception as e:
            logger.error(f"Failed to save cluster manager file: {e}")
