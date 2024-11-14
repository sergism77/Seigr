# src/seigr_cell/seigr_cell_decoder.py

import logging
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.cbor_utils import decode_data as cbor_decode
from src.seigr_protocol.compiled.integrity_pb2 import VerificationStatus
from src.crypto.key_derivation import derive_key

# Initialize logging for the SeigrCellDecoder
logger = logging.getLogger(__name__)

class SeigrCellDecoder:
    """Decodes and verifies Seigr Cells with secure decryption and integrity validation."""

    def __init__(self, segment_id, hash_depth=4, use_senary=True):
        """
        Initializes a SeigrCellDecoder with specified cryptographic settings.

        Args:
            segment_id (str): Identifier for the data segment.
            hash_depth (int): Depth of the hierarchical hash.
            use_senary (bool): Whether to use senary encoding.
        """
        self.segment_id = segment_id
        self.hash_depth = hash_depth
        self.use_senary = use_senary

    def decode(self, encoded_cell: bytes, password: str = None) -> tuple:
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
        try:
            payload = cbor_decode(encoded_cell)
            encrypted_data = payload["data"]
            metadata = payload.get("metadata", {})
            primary_hash = payload["primary_hash"]
            hash_tree = payload["hash_tree"]
            logger.info(f"Decoded CBOR payload for segment {self.segment_id}")
        except Exception as e:
            logger.error(f"Failed to decode CBOR for segment {self.segment_id}: {e}")
            raise ValueError("Failed to decode Seigr Cell")

        # Initialize HyphaCrypt for decryption and integrity verification
        hypha = HyphaCrypt(b'', self.segment_id, self.hash_depth, self.use_senary)

        # Generate decryption key and decrypt data if a password is provided
        try:
            key = derive_key(password, hypha.generate_salt()) if password else hypha.generate_encryption_key()
            decrypted_data = hypha.decrypt_data(encrypted_data, key)
            logger.info(f"Data decrypted for segment {self.segment_id}")
        except Exception as e:
            logger.error(f"Decryption failed for segment {self.segment_id}: {e}")
            raise ValueError("Failed to decrypt Seigr Cell data")

        # Verify data integrity
        verification_results = hypha.verify_integrity(hash_tree)
        if verification_results["status"] != VerificationStatus.VERIFIED:
            logger.warning(f"Integrity verification failed for segment {self.segment_id}")
            raise ValueError("Data integrity verification failed.")
        
        logger.info(f"Seigr Cell decoded and verified for segment {self.segment_id}")
        return decrypted_data, metadata

    def verify_integrity(self, encoded_cell: bytes, reference_hash_tree: dict) -> bool:
        """
        Verifies the integrity of the Seigr Cell's data against a reference hash tree.

        Args:
            encoded_cell (bytes): The encoded cell to verify.
            reference_hash_tree (dict): Reference hash tree for integrity comparison.

        Returns:
            bool: True if verification succeeds, False otherwise.
        """
        logger.debug(f"Starting integrity verification for segment {self.segment_id}")
        
        try:
            # Decode the CBOR payload
            payload = cbor_decode(encoded_cell)
            encrypted_data = payload["data"]
            primary_hash = payload["primary_hash"]
            hash_tree = payload["hash_tree"]

            # Initialize HyphaCrypt with encrypted data
            hypha = HyphaCrypt(encrypted_data, self.segment_id, self.hash_depth, self.use_senary)
            current_tree = hypha.compute_layered_hashes()
            integrity_status = hypha.verify_integrity(reference_hash_tree, partial_depth=self.hash_depth)

            # Integrity check comparison
            success = integrity_status["status"] == "success"
            if success:
                logger.info(f"Integrity verified for Seigr Cell segment {self.segment_id}")
            else:
                logger.warning(f"Integrity verification failed for Seigr Cell segment {self.segment_id}")
            return success
        except Exception as e:
            logger.error(f"Integrity verification error for segment {self.segment_id}: {e}")
            raise ValueError("Failed integrity verification")
