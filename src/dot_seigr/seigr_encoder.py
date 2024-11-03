import os
import logging
import zlib
from .seigr_file import SeigrFile
from .seigr_cluster_manager import SeigrClusterManager
from .seigr_constants import SEIGR_SIZE, HEADER_SIZE, BLANK_SPACE_RATIO

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeigrEncoder:
    def __init__(self, data: bytes, creator_id: str, base_dir: str):
        """
        Initializes the SeigrEncoder for encoding data into .seigr files.

        Args:
            data (bytes): The binary data to encode.
            creator_id (str): Unique identifier for the data creator.
            base_dir (str): Directory path where .seigr files and clusters are stored.
        """
        self.data = data
        self.creator_id = creator_id
        self.base_dir = base_dir
        self.blank_space = int((SEIGR_SIZE - HEADER_SIZE) * BLANK_SPACE_RATIO)  # Reserve space per .seigr file

    def _compress_and_segment_data(self):
        """
        Compresses and segments the data to fit into .seigr files with reserved space.

        Returns:
            list: Segmented data chunks as byte strings.
        """
        try:
            compressed_data = zlib.compress(self.data)
            segment_size = SEIGR_SIZE - HEADER_SIZE - self.blank_space
            segments = [
                compressed_data[i:i + segment_size]
                for i in range(0, len(compressed_data), segment_size)
            ]
            logger.debug(f"Data compressed and segmented into {len(segments)} parts.")
            return segments
        except Exception as e:
            logger.error(f"Data compression and segmentation failed: {e}")
            raise

    def encode(self):
        """
        Encodes data into .seigr files, manages cluster association, and logs the encoding process.
        """
        # Initialize cluster manager
        cluster_manager = SeigrClusterManager(self.creator_id)
        
        # Prepare the data segments
        try:
            segments = self._compress_and_segment_data()
        except Exception as e:
            logger.error(f"Failed to prepare data for encoding: {e}")
            return

        # Process each segment, saving it as a .seigr file and associating with the cluster
        for index, segment in enumerate(segments):
            try:
                seigr_file = SeigrFile(data=segment, creator_id=self.creator_id)
                file_path = seigr_file.save_to_disk(self.base_dir)
                cluster_manager.add_segment(seigr_file.hash)
                logger.info(f"Encoded segment {index + 1}/{len(segments)}: Saved to {file_path}")
            except Exception as e:
                logger.error(f"Failed to encode segment {index + 1}: {e}")
        
        # Save the cluster file after processing all segments
        try:
            cluster_manager.save_cluster(self.base_dir)
            logger.info("Encoding process completed successfully.")
        except Exception as e:
            logger.error(f"Failed to save cluster manager file: {e}")
