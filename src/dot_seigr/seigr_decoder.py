# src/dot_seigr/seigr_decoder.py

import os
import json
import logging
from .seigr_file import SeigrFile
from src.crypto.hypha_crypt import decode_from_senary

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeigrDecoder:
    def __init__(self, cluster_files: list, base_dir: str):
        """
        Initialize the SeigrDecoder with a list of cluster files and a base directory.

        Args:
            cluster_files (list): List of cluster (seed) file paths.
            base_dir (str): Directory where encoded .seigr files are stored.
        """
        self.cluster_files = cluster_files
        self.base_dir = base_dir

    def decode(self) -> bytes:
        """
        Decodes and reassembles the original data from multiple encoded segments.

        Returns:
            bytes: Reconstructed original binary data.
        """
        decoded_data = b''

        for cluster_file in self.cluster_files:
            cluster_path = os.path.join(self.base_dir, cluster_file)
            try:
                with open(cluster_path, 'r') as f:
                    cluster_data = json.load(f)
                
                logger.info(f"Processing cluster file: {cluster_file}")
                
                # Iterate through each segment hash in the cluster file
                for segment_hash in cluster_data["associated_files"]:
                    segment_path = os.path.join(self.base_dir, f"{segment_hash}.seigr")
                    try:
                        with open(segment_path, 'r') as seg_file:
                            seigr_content = json.load(seg_file)
                            seigr_data = seigr_content.get("data")

                            # Decode the segment data
                            decoded_segment = decode_from_senary(seigr_data)
                            decoded_data += decoded_segment
                            logger.debug(f"Decoded segment {segment_hash} successfully.")
                    except FileNotFoundError:
                        logger.error(f"Segment file {segment_path} not found.")
                    except Exception as e:
                        logger.error(f"Error decoding segment {segment_hash}: {e}")

            except FileNotFoundError:
                logger.error(f"Cluster file {cluster_path} not found.")
            except Exception as e:
                logger.error(f"Error processing cluster file {cluster_file}: {e}")

        return decoded_data
