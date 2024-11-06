import os
import logging
from src.dot_seigr.integrity import verify_integrity
from src.crypto.hypha_crypt import decode_from_senary
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SeigrCluster
from src.dot_seigr.seigr_file import SeigrFile  # Import Protobuf-based SeigrFile structure

logger = logging.getLogger(__name__)

class SeigrDecoder:
    def __init__(self, cluster_files: list, base_dir: str):
        """
        Initializes the SeigrDecoder with cluster files and base directory.

        Args:
            cluster_files (list): List of cluster Protobuf file paths to decode.
            base_dir (str): Base directory where cluster and .seigr files are located.
        """
        self.cluster_files = cluster_files
        self.base_dir = base_dir

    def decode(self) -> str:
        """
        Decodes and reassembles the original data from multiple encoded segments.

        Returns:
            str: Path to the reassembled decoded file, or None if decoding failed.
        """
        decoded_data = bytearray()
        output_filename = None

        for cluster_file in self.cluster_files:
            cluster_path = os.path.join(self.base_dir, cluster_file)

            try:
                # Load cluster data from Protobuf
                with open(cluster_path, "rb") as f:
                    cluster = SeigrCluster()
                    cluster.ParseFromString(f.read())
                logger.info(f"Processing cluster file: {cluster_file}")

                # Retrieve filename and extension from the Protobuf metadata
                if not output_filename:
                    original_filename = cluster.file_metadata.original_filename
                    original_extension = cluster.file_metadata.original_extension
                    output_filename = f"{original_filename or 'decoded_output'}{original_extension or ''}"

                # Retrieve and sort segments by index
                segments = sorted(
                    [(seg.index, seg.hash) for seg in cluster.segments],
                    key=lambda x: x[0]
                )

                # Decode each segment and verify integrity
                for index, segment_hash in segments:
                    if not segment_hash:
                        logger.warning(f"Missing hash for segment {index} in cluster file {cluster_file}.")
                        continue

                    segment_path = os.path.join(self.base_dir, f"{segment_hash}.seigr")
                    try:
                        # Load segment data from Protobuf-based .seigr file
                        seigr_file = SeigrFile.load_from_disk(segment_path)
                        seigr_data = seigr_file.data
                        stored_hash = seigr_file.metadata.primary_hash

                        # Validate data integrity
                        if not verify_integrity(stored_hash, seigr_data):
                            logger.error(f"Integrity check failed for segment {segment_hash}. Skipping.")
                            continue

                        # Decode and append the data
                        decoded_segment = decode_from_senary(seigr_data)
                        decoded_data.extend(decoded_segment)
                        logger.debug(f"Decoded segment {segment_hash} at index {index} successfully.")

                    except FileNotFoundError:
                        logger.error(f"Segment file {segment_path} not found.")
                    except Exception as e:
                        logger.error(f"Error decoding segment {segment_hash}: {e}")

            except FileNotFoundError:
                logger.error(f"Cluster file {cluster_path} not found.")
            except Exception as e:
                logger.error(f"Error processing cluster file {cluster_file}: {e}")

        # Write decoded output if data was successfully assembled
        if decoded_data:
            decoded_file_path = os.path.join(self.base_dir, output_filename)
            with open(decoded_file_path, "wb") as f:
                f.write(decoded_data)
            logger.info(f"Decoded data saved to {decoded_file_path} with size: {len(decoded_data)} bytes.")
            return decoded_file_path
        else:
            logger.warning("No data was decoded from the provided cluster files.")
            return None
