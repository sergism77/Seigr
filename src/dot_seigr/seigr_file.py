# src/dot_seigr/seigr_file.py

import os
import json
import hashlib
import logging
from .seigr_constants import HEADER_SIZE

logger = logging.getLogger(__name__)

class SeigrFile:
    def __init__(self, data: str, creator_id: str, file_type="senary"):
        """
        Initialize a SeigrFile instance.
        
        Args:
            data (str): Senary-encoded string representing the data.
            creator_id (str): Unique identifier for the creator.
            file_type (str): Type of the file (default: "senary").
        """
        self.data = data  # Store as senary-encoded string
        self.creator_id = creator_id
        self.file_type = file_type
        self.hash = self.generate_hash(data)

    def generate_hash(self, data: str) -> str:
        """Generates SHA-256 hash for the data to uniquely identify the file contents."""
        hash_value = hashlib.sha256(data.encode()).hexdigest()
        logger.debug(f"Generated SHA-256 hash: {hash_value}")
        return hash_value

    def save_to_disk(self, base_dir: str) -> str:
        """
        Saves the .seigr file as a JSON structure on disk.

        Args:
            base_dir (str): Directory to save the .seigr file.

        Returns:
            str: Path to the saved file.
        """
        filename = f"{self.hash}.seigr"
        file_path = os.path.join(base_dir, filename)

        # Construct .seigr file content with reserved header space
        seigr_content = {
            "header": {
                "creator_id": self.creator_id,
                "file_type": self.file_type,
                "hash": self.hash,
                "header_size": HEADER_SIZE  # Indicate reserved header size
            },
            "data": self.data  # Store senary-encoded data as a string
        }

        # Ensure the directory exists
        os.makedirs(base_dir, exist_ok=True)

        # Write .seigr file as JSON
        with open(file_path, 'w') as f:
            json.dump(seigr_content, f)
        
        logger.info(f".seigr file saved at {file_path}")
        return file_path
