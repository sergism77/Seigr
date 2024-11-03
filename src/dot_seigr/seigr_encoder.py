# src/dot_seigr/seigr_encoder.py

import os
import logging
from .compression import encode_data  # Adjusted for direct senary encoding
from .seigr_file import SeigrFile
from .seigr_cluster_manager import SeigrClusterManager
from .seigr_constants import SEIGR_SIZE, TARGET_BINARY_SEGMENT_SIZE, HEADER_SIZE

logger = logging.getLogger(__name__)

class SeigrEncoder:
    def __init__(self, data: bytes, creator_id: str, base_dir: str):
        self.data = data
        self.creator_id = creator_id
        self.base_dir = base_dir

    def _segment_data(self):
        """
        Split data into fixed binary segments that result in ~539 KB after encoding.

        Returns:
            list: List of binary data chunks before encoding.
        """
        segments = [
            self.data[i:i + TARGET_BINARY_SEGMENT_SIZE]
            for i in range(0, len(self.data), TARGET_BINARY_SEGMENT_SIZE)
        ]
        logger.debug(f"Data segmented into {len(segments)} parts, each ~{TARGET_BINARY_SEGMENT_SIZE} bytes.")
        return segments

    def encode(self):
        """
        Encode data into .seigr files of target size and manage cluster associations.
        """
        cluster_manager = SeigrClusterManager(self.creator_id)
        
        # Segment data before encoding
        segments = self._segment_data()

        # Encode each segment and save as a .seigr file
        for index, segment in enumerate(segments):
            try:
                # Encode segment directly into senary format
                senary_data = encode_data(segment)
                # Save to .seigr file with header and metadata
                seigr_file = SeigrFile(data=senary_data.encode('utf-8'), creator_id=self.creator_id)
                file_path = seigr_file.save_to_disk(self.base_dir)
                # Add to cluster manager
                cluster_manager.add_segment(seigr_file.hash)
                logger.info(f"Encoded segment {index + 1}/{len(segments)}: Saved to {file_path}")
            except Exception as e:
                logger.error(f"Failed to encode segment {index + 1}: {e}")
        
        # Save cluster metadata
        try:
            cluster_manager.save_cluster(self.base_dir)
            logger.info("Encoding process completed successfully.")
        except Exception as e:
            logger.error(f"Failed to save cluster manager file: {e}")
