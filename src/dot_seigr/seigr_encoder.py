# src/dot_seigr/seigr_encoder.py

import os
import logging
from src.crypto.hypha_crypt import encode_to_senary
from .seigr_file import SeigrFile
from .seigr_cluster_manager import SeigrClusterManager
from .seigr_constants import SEIGR_SIZE, TARGET_BINARY_SEGMENT_SIZE

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeigrEncoder:
    def __init__(self, data: bytes, creator_id: str, base_dir: str):
        self.data = data
        self.creator_id = creator_id
        self.base_dir = base_dir

    def segment_data(self):
        """Split data into fixed-size binary segments based on TARGET_BINARY_SEGMENT_SIZE."""
        return [self.data[i:i + TARGET_BINARY_SEGMENT_SIZE] for i in range(0, len(self.data), TARGET_BINARY_SEGMENT_SIZE)]

    def encode(self):
        """Encode data into .seigr files with direct segmentation."""
        cluster_manager = SeigrClusterManager(self.creator_id)
        segments = self.segment_data()

        # Process each segment
        for index, segment in enumerate(segments):
            try:
                senary_data = encode_to_senary(segment)
                seigr_file = SeigrFile(data=senary_data, creator_id=self.creator_id)
                file_path = seigr_file.save_to_disk(self.base_dir)
                cluster_manager.add_segment(seigr_file.hash)
                logger.info(f"Encoded segment {index + 1}/{len(segments)}: Saved to {file_path}")
            except Exception as e:
                logger.error(f"Failed to encode segment {index + 1}: {e}")

        # Save the cluster manager file
        try:
            cluster_manager.save_cluster(self.base_dir)
            logger.info("Encoding process completed successfully.")
        except Exception as e:
            logger.error(f"Failed to save cluster manager file: {e}")
