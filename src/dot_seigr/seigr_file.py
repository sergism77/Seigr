# src/dot_seigr/seigr_file.py

import os
import zlib
import json
from datetime import datetime, timezone
import logging
from src.crypto.hypha_crypt import encode_to_senary, generate_hash, decode_from_senary
from .seigr_constants import SEIGR_SIZE, HEADER_SIZE, MIN_REPLICATION

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class SeigrFile:
    def __init__(self, data: bytes, creator_id: str, previous_hash: str = None, file_type: str = "binary"):
        self.data = data
        self.creator_id = creator_id
        self.previous_hash = previous_hash or ""
        self.file_type = file_type
        self.version = "1.0"
        self.replication_count = MIN_REPLICATION
        self.hash = ""
        self.senary_data = ""
        self.associated_segments = []

    def compress_data(self) -> bytes:
        """Compress the data using zlib for storage efficiency."""
        return zlib.compress(self.data)

    def encode_data(self, compressed_data: bytes) -> str:
        """Encode compressed data to senary format for .seigr file storage."""
        return encode_to_senary(compressed_data)

    def create_file_structure(self) -> dict:
        """Create the .seigr file dictionary with metadata and encoded data."""
        compressed_data = self.compress_data()
        self.senary_data = self.encode_data(compressed_data)
        self.hash = generate_hash(self.senary_data)

        return {
            "header": {
                "version": self.version,
                "file_type": self.file_type,
                "creator_id": self.creator_id,
                "previous_hash": self.previous_hash,
                "hash": self.hash,
                "replication_count": self.replication_count,
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            "data": self.senary_data
        }

    def save_to_disk(self, directory: str) -> str:
        """Save .seigr file structure to disk in JSON format."""
        file_structure = self.create_file_structure()
        filename = f"{self.hash}.seigr"
        file_path = os.path.join(directory, filename)

        with open(file_path, 'w') as f:
            json.dump(file_structure, f, indent=4)
        logger.info(f".seigr file saved at {file_path}")
        return file_path
