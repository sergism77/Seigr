# src/seigr_cell/seigr_cell_encoder.py

import logging
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.cbor_utils import encode_data as cbor_encode, decode_data as cbor_decode

# Initialize logging for the SeigrCellEncoder
logger = logging.getLogger(__name__)

class SeigrCellEncoder:
    """Encodes and decodes data into Seigr Cells with HyphaCrypt encryption and integrity verification."""

    def __init__(self, segment_id, hash_depth=4, use_senary=True):
        """
        Initializes a SeigrCellEncoder with specified cryptographic settings.

        Args:
            segment_id (str): Identifier for the data segment.
            hash_depth (int): Depth of the hierarchical hash.
            use_senary (bool): Whether to use senary encoding.
        """
        self.segment_id = segment_id
        self.hash_depth = hash_depth
        self.use_senary = use_senary

    def encode(self, data, metadata=None, password=None):
        """
        Encodes data and metadata into a Seigr Cell format with encryption and integrity.

        Args:
            data (bytes): Data to encode.
            metadata (dict): Metadata to include in encoding.
            password (str): Optional password for encryption.

        Returns:
            bytes: The encoded and encrypted Seigr Cell.
        """
        logger.debug(f"Encoding data for segment {self.segment_id}")

        # Initialize HyphaCrypt for hashing, logging, and encryption
        hypha = HyphaCrypt(data, self.segment_id, self.hash_depth, self.use_senary)

        # Generate encryption key
        key = hypha.generate_encryption_key(password)
        encrypted_data = hypha.encrypt_data(key)

        # Compute integrity hashes
        primary_hash = hypha.compute_primary_hash()
        hash_tree = hypha.compute_layered_hashes()

        # Prepare CBOR-encoded payload with metadata, encrypted data, and hash tree
        seigr_cell_payload = {
            "data": encrypted_data,
            "metadata": metadata or {},
            "primary_hash": primary_hash,
            "hash_tree": hash_tree,
        }
        encoded_cell = cbor_encode(seigr_cell_payload)
        logger.info(f"Seigr Cell encoded for segment {self.segment_id}")

        return encoded_cell

    def decode(self, encoded_cell, password=None):
        """
        Decodes a Seigr Cell, decrypting and verifying its integrity.

        Args:
            encoded_cell (bytes): The encoded cell to decode.
            password (str): Optional password for decryption.

        Returns:
            tuple: Original data (bytes) and metadata (dict).
        """
        logger.debug(f"Decoding Seigr Cell for segment {self.segment_id}")

        # Decode CBOR payload
        payload = cbor_decode(encoded_cell)
        encrypted_data = payload["data"]
        metadata = payload["metadata"]
        primary_hash = payload["primary_hash"]
        hash_tree = payload["hash_tree"]

        # Initialize HyphaCrypt for decryption and verification
        hypha = HyphaCrypt(b'', self.segment_id, self.hash_depth, self.use_senary)

        # Generate decryption key and decrypt data
        key = hypha.generate_encryption_key(password)
        decrypted_data = hypha.decrypt_data(encrypted_data, key)

        # Verify data integrity by comparing computed and stored hash trees
        hypha.data = decrypted_data
        verification_results = hypha.verify_integrity(hash_tree)
        
        if verification_results["status"] != "success":
            logger.warning(f"Integrity verification failed for segment {self.segment_id}")
            raise ValueError("Data integrity verification failed.")
        
        logger.info(f"Seigr Cell decoded and verified for segment {self.segment_id}")

        return decrypted_data, metadata
