# src/dot_seigr/seigr_decoder.py

import os
import xml.etree.ElementTree as ET
import logging
from src.crypto.hypha_crypt import decode_from_senary, verify_integrity
import json

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeigrDecoder:
    def __init__(self, cluster_files: list, base_dir: str):
        """
        Initializes the SeigrDecoder with cluster files and base directory.

        Args:
            cluster_files (list): List of cluster XML file paths to decode.
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
                # Parse XML structure
                tree = ET.parse(cluster_path)
                root = tree.getroot()

                logger.info(f"Processing cluster file: {cluster_file}")

                # Retrieve original filename and extension from XML metadata
                if not output_filename:
                    original_filename = root.findtext("OriginalFilename")
                    original_extension = root.findtext("OriginalExtension")

                    # Handle missing filename or extension
                    if not original_filename or not original_extension:
                        logger.warning(f"Missing original filename or extension in cluster file {cluster_file}.")
                        output_filename = "decoded_output"  # Default fallback
                    else:
                        output_filename = f"{original_filename}{original_extension}"

                # Retrieve and sort segments by index from the XML metadata
                segments = sorted(
                    [(int(segment.get("index", -1)), segment.get("hash")) for segment in root.find("Segments")],
                    key=lambda x: x[0]
                )

                # Decode each segment in order and append to decoded data
                for index, segment_hash in segments:
                    if segment_hash is None:
                        logger.warning(f"Segment index {index} in cluster file {cluster_file} is missing a hash.")
                        continue

                    segment_path = os.path.join(self.base_dir, f"{segment_hash}.seigr")
                    try:
                        with open(segment_path, 'r') as seg_file:
                            seigr_content = json.load(seg_file)  # JSON format for each .seigr segment
                            seigr_data = seigr_content.get("data")

                            # Check for missing data field
                            if not seigr_data:
                                logger.warning(f"Data field missing in segment {segment_hash}. Skipping segment.")
                                continue

                            # Retrieve hash from header, handling potential missing fields
                            header = seigr_content.get("header", {})
                            stored_hash = header.get("hash")
                            if not stored_hash:
                                logger.warning(f"Hash missing in header of segment {segment_hash}. Skipping integrity check.")

                            # Verify integrity if stored_hash is available
                            if stored_hash and not verify_integrity(stored_hash, seigr_data):
                                logger.error(f"Integrity check failed for segment {segment_hash}. Skipping segment.")
                                continue

                            # Decode the senary data back to binary
                            decoded_segment = decode_from_senary(seigr_data)
                            decoded_data.extend(decoded_segment)
                            logger.debug(f"Decoded segment {segment_hash} at index {index} successfully.")

                    except FileNotFoundError:
                        logger.error(f"Segment file {segment_path} not found.")
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON format in segment file {segment_path}.")
                    except Exception as e:
                        logger.error(f"Error decoding segment {segment_hash}: {e}")

            except ET.ParseError as e:
                logger.error(f"Error parsing XML cluster file {cluster_file}: {e}")
            except FileNotFoundError:
                logger.error(f"Cluster file {cluster_path} not found.")
            except Exception as e:
                logger.error(f"Error processing cluster file {cluster_file}: {e}")

        # Write decoded output to file if data was decoded
        if decoded_data:
            decoded_file_path = os.path.join(self.base_dir, output_filename)
            with open(decoded_file_path, "wb") as f:
                f.write(decoded_data)
            logger.info(f"Decoded data saved to {decoded_file_path} with size: {len(decoded_data)} bytes.")
            return decoded_file_path
        else:
            logger.warning("No data was decoded from the provided cluster files.")
            return None
