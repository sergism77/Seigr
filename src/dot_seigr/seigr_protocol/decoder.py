import os
import xml.etree.ElementTree as ET
import logging
import json
from dot_seigr.integrity import verify_integrity
from src.crypto.hypha_crypt import decode_from_senary

logger = logging.getLogger(__name__)

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

                # Retrieve filename and extension from XML metadata
                if not output_filename:
                    original_filename = root.findtext("OriginalFilename")
                    original_extension = root.findtext("OriginalExtension")
                    output_filename = f"{original_filename or 'decoded_output'}{original_extension or ''}"

                # Retrieve and sort segments by index
                segments = sorted(
                    [(int(segment.get("index", -1)), segment.get("hash")) for segment in root.findall("Segments/Segment")],
                    key=lambda x: x[0]
                )

                # Decode each segment and verify integrity
                for index, segment_hash in segments:
                    if not segment_hash:
                        logger.warning(f"Missing hash for segment {index} in cluster file {cluster_file}.")
                        continue

                    segment_path = os.path.join(self.base_dir, f"{segment_hash}.seigr")
                    try:
                        with open(segment_path, 'r') as seg_file:
                            seigr_content = json.load(seg_file)
                            seigr_data = seigr_content.get("data")
                            stored_hash = seigr_content.get("header", {}).get("hash")

                            # Validate data integrity
                            if stored_hash and not verify_integrity(stored_hash, seigr_data):
                                logger.error(f"Integrity check failed for segment {segment_hash}. Skipping.")
                                continue

                            # Decode and append the data
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
