import os
import logging
from src.crypto.encoding_utils import encode_to_senary
from src.dot_seigr.seigr_protocol.manager import SeigrClusterManager
from src.dot_seigr.seigr_file import SeigrFile
from src.dot_seigr.seigr_constants import TARGET_BINARY_SEGMENT_SIZE

logger = logging.getLogger(__name__)

class SeigrEncoder:
    def __init__(self, data: bytes, creator_id: str, base_dir: str, original_filename: str):
        """
        Initializes the SeigrEncoder with data, creator information, and file path settings.

        Args:
            data (bytes): The raw data to be segmented and encoded.
            creator_id (str): Unique identifier for the creator of the data.
            base_dir (str): Directory to save encoded segments and cluster files.
            original_filename (str): Name of the original file.
        """
        self.data = data
        self.creator_id = creator_id
        self.base_dir = base_dir
        self.original_filename = original_filename
        self.original_extension = os.path.splitext(original_filename)[1]
        self.cluster_manager = SeigrClusterManager(self.creator_id, self.original_filename, self.original_extension)

    def segment_data(self):
        """
        Segments the data into chunks of TARGET_BINARY_SEGMENT_SIZE for encoding.

        Returns:
            list: List of segmented data chunks.
        """
        segment_size = TARGET_BINARY_SEGMENT_SIZE
        segments = [self.data[i:i + segment_size] for i in range(0, len(self.data), segment_size)]
        logger.debug(f"Data segmented into {len(segments)} parts with each segment up to {segment_size} bytes.")
        return segments

    def encode(self):
        """
        Main encoding process that segments the data, encodes each segment in senary format,
        and saves them as .seigr files with cluster metadata.
        """
        # Ensure base directory exists for encoded files
        os.makedirs(self.base_dir, exist_ok=True)
        logger.info(f"Base directory for encoded files set to {self.base_dir}")

        try:
            segments = self.segment_data()
            if not segments:
                logger.error("No segments were created. Exiting encoding process.")
                return
        except Exception as e:
            logger.error(f"Error during data segmentation: {e}")
            return

        for index, segment in enumerate(segments):
            try:
                # Encode data in senary format for each segment
                senary_data = encode_to_senary(segment)
                logger.debug(f"Encoding segment {index + 1}/{len(segments)} with senary encoding.")

                # Create SeigrFile instance for each segment
                seigr_file = SeigrFile(
                    data=senary_data,
                    creator_id=self.creator_id,
                    index=index,
                    file_type="senary"
                )

                # Save the encoded segment to disk and register with the cluster manager
                file_path = seigr_file.save_to_disk(self.base_dir)
                self.cluster_manager.add_segment(str(seigr_file.hash), index)
                logger.info(f"Encoded segment {index + 1}/{len(segments)}: Saved to {file_path}")

            except Exception as e:
                logger.error(f"Failed to encode or save segment {index + 1}: {e}")

        # Save the completed cluster structure
        try:
            self.cluster_manager.save_cluster(self.base_dir)
            logger.info("Encoding process completed successfully.")
        except Exception as e:
            logger.error(f"Failed to save cluster manager file: {e}")
