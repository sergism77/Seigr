import logging
import os

from dot_seigr.capsule.seigr_integrity import compute_integrity, verify_integrity
from dot_seigr.seigr_file import SeigrFile
from src.crypto.hypha_crypt import decode_from_senary, encode_to_senary
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import (
    SeigrCluster,
)

logger = logging.getLogger(__name__)


class SeigrEncoder:
    """
    Encodes raw data into senary format segments and manages their storage in `.seigr` files.
    """

    def __init__(
        self,
        data: bytes,
        output_dir: str,
        max_segment_size: int = 4096,
        creator_id: str = "system",
    ):
        """
        Initializes the SeigrEncoder with data, output directory, and segment size.

        Args:
            data (bytes): The raw data to be encoded.
            output_dir (str): Directory where encoded `.seigr` segments will be saved.
            max_segment_size (int): Maximum size of each encoded segment in bytes.
            creator_id (str): Identifier for the data creator, default is "system".
        """
        self.data = data
        self.output_dir = output_dir
        self.max_segment_size = max_segment_size
        self.creator_id = creator_id

    def encode(self) -> list:
        """
        Encodes and splits the data into segments, then saves each as a `.seigr` file.

        Returns:
            list: A list of file paths to the saved `.seigr` segments.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        segment_files = []

        for index in range(0, len(self.data), self.max_segment_size):
            segment_data = self.data[index : index + self.max_segment_size]

            # Encode data and compute integrity
            encoded_segment = encode_to_senary(segment_data)
            integrity_hash = compute_integrity(encoded_segment)
            segment_filename = f"{integrity_hash}.seigr"

            # Create a SeigrFile instance to save the segment
            segment_file = SeigrFile(
                data=encoded_segment.encode(),
                creator_id=self.creator_id,
                index=index // self.max_segment_size,
                file_type="senary",
            )
            segment_file_path = os.path.join(self.output_dir, segment_filename)
            segment_file.save_to_disk(segment_file_path)

            segment_files.append(segment_file_path)
            logger.info(
                f"Saved encoded segment {index // self.max_segment_size} as {segment_filename}"
            )

        return segment_files


class SeigrDecoder:
    """
    Decodes and reassembles data from `.seigr` files containing senary encoded segments.
    """

    def __init__(self, cluster_files: list, base_dir: str):
        """
        Initializes the SeigrDecoder with cluster files and base directory.

        Args:
            cluster_files (list): List of cluster Protobuf file paths to decode.
            base_dir (str): Base directory where cluster and `.seigr` files are located.
        """
        self.cluster_files = cluster_files
        self.base_dir = base_dir

    def decode(self) -> str:
        """
        Decodes and reassembles the original data from encoded segments.

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

                # Retrieve filename and extension from the metadata
                if not output_filename:
                    original_filename = cluster.file_metadata.original_filename
                    original_extension = cluster.file_metadata.original_extension
                    output_filename = f"{original_filename or 'decoded_output'}{original_extension or ''}"

                # Retrieve and sort segments by index
                segments = sorted(
                    [(seg.index, seg.hash) for seg in cluster.segments],
                    key=lambda x: x[0],
                )

                # Decode each segment and verify integrity
                for index, segment_hash in segments:
                    if not segment_hash:
                        logger.warning(
                            f"Missing hash for segment {index} in cluster file {cluster_file}."
                        )
                        continue

                    segment_path = os.path.join(self.base_dir, f"{segment_hash}.seigr")
                    try:
                        # Load segment data from `.seigr` file
                        seigr_file = SeigrFile.load_from_disk(segment_path)
                        seigr_data = seigr_file.data
                        stored_hash = seigr_file.metadata.primary_hash

                        # Validate data integrity
                        if not verify_integrity(stored_hash, seigr_data):
                            logger.error(
                                f"Integrity check failed for segment {segment_hash}. Skipping."
                            )
                            continue

                        # Decode and append the data
                        decoded_segment = decode_from_senary(seigr_data)
                        decoded_data.extend(decoded_segment)
                        logger.debug(
                            f"Decoded segment {segment_hash} at index {index} successfully."
                        )

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
            logger.info(
                f"Decoded data saved to {decoded_file_path} with size: {len(decoded_data)} bytes."
            )
            return decoded_file_path
        else:
            logger.warning("No data was decoded from the provided cluster files.")
            return None
