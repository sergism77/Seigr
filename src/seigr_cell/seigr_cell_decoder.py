# src/seigr_cell/seigr_cell_decoder.py

import logging
from src.crypto.cbor_utils import decode_data as cbor_decode
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.key_derivation import derive_key
from src.seigr_protocol.compiled.hashing_pb2 import VerificationStatus
from src.logger.secure_logger import secure_logger

# Initialize logging for the SeigrCellDecoder
logger = logging.getLogger(__name__)


class SeigrCellDecoder:
    """Decodes and verifies Seigr Cells with secure decryption and integrity validation."""

    def __init__(self, segment_id: str, hash_depth: int = 4, use_senary: bool = True):
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

        Raises:
            ValueError: If decoding, decryption, or integrity verification fails.
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
            secure_logger.log_audit_event(
                severity=3,
                category="Decoding",
                message=f"Failed to decode CBOR for segment {self.segment_id}: {e}",
                sensitive=True,
            )
            raise ValueError("Failed to decode Seigr Cell")

        # Initialize HyphaCrypt for decryption and integrity verification
        hypha = HyphaCrypt(b"", self.segment_id, self.hash_depth, self.use_senary)

        # Generate decryption key and decrypt data if a password is provided
        try:
            key = (
                derive_key(password, hypha.generate_salt())
                if password
                else hypha.generate_encryption_key()
            )
            decrypted_data = hypha.decrypt_data(encrypted_data, key)
            logger.info(f"Data decrypted for segment {self.segment_id}")
        except Exception as e:
            logger.error(f"Decryption failed for segment {self.segment_id}: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Decryption",
                message=f"Decryption failed for segment {self.segment_id}: {e}",
                sensitive=True,
            )
            raise ValueError("Failed to decrypt Seigr Cell data")

        # Verify data integrity
        try:
            verification_results = hypha.verify_integrity(hash_tree)
            if verification_results["status"] != VerificationStatus.VERIFIED:
                logger.warning(f"Integrity verification failed for segment {self.segment_id}")
                secure_logger.log_audit_event(
                    severity=2,
                    category="Integrity",
                    message=f"Integrity verification failed for segment {self.segment_id}",
                    sensitive=True,
                )
                raise ValueError("Data integrity verification failed.")
        except Exception as e:
            logger.error(f"Integrity verification error for segment {self.segment_id}: {e}")
            raise ValueError("Integrity verification failed.")

        logger.info(f"Seigr Cell decoded and verified for segment {self.segment_id}")
        secure_logger.log_audit_event(
            severity=1,
            category="Decoding",
            message=f"Seigr Cell successfully decoded for segment {self.segment_id}",
            sensitive=False,
        )
        return decrypted_data, metadata

