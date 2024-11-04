# src/dot_seigr/seigr_decoder.py

import os
import xml.etree.ElementTree as ET
import logging
from src.crypto.hypha_crypt import decode_from_senary
import json

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeigrDecoder:
    def __init__(self, cluster_files: list, base_dir: str):
        self.cluster_files = cluster_files
        self.base_dir = base_dir

    def decode(self) -> str:
        """Decodes and reassembles the original data from multiple encoded segments."""
        decoded_data = bytearray()
        output_filename = None

        for cluster_file in self.cluster_files:
            cluster_path = os.path.join(self.base_dir, cluster_file)
            
            try:
                # Parse XML structure
                tree = ET.parse(cluster_path)
                root = tree.getroot()

                logger.info(f"Processing cluster file: {cluster_file}")

                # Get original filename and extension from XML metadata
                if not output_filename:
                    original_filename = root.find("OriginalFilename").text
                    original_extension = root.find("OriginalExtension").text
                    output_filename = f"{original_filename}{original_extension}"

                # Retrieve segment data from XML
                segments = []
                for segment in root.find("Segments"):
                    segment_hash = segment.get("hash")
                    segment_index = int(segment.get("index"))
                    segments.append((segment_index, segment_hash))

                # Sort segments by index
                segments.sort(key=lambda x: x[0])

                # Decode each segment in order and append to decoded data
                for index, segment_hash in segments:
                    segment_path = os.path.join(self.base_dir, f"{segment_hash}.seigr")
                    try:
                        with open(segment_path, 'r') as seg_file:
                            seigr_content = json.load(seg_file)  # JSON format for each .seigr segment
                            seigr_data = seigr_content.get("data")

                            # Decode the senary data back to binary
                            decoded_segment = decode_from_senary(seigr_data)
                            decoded_data.extend(decoded_segment)
                            logger.debug(f"Decoded segment {segment_hash} at index {index} successfully.")
                    except FileNotFoundError:
                        logger.error(f"Segment file {segment_path} not found.")
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
