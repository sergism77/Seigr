# src/seigr_cell/seigr_cell_encoder.py

import logging
from src.crypto.cbor_utils import decode_data as cbor_decode, encode_data as cbor_encode
from src.crypto.hypha_crypt import HyphaCrypt
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.hashing_pb2 import VerificationStatus

# Initialize logging for the SeigrCellEncoder
logger = logging.getLogger(__name__)


class SeigrCellEncoder:
    """
    Encodes and decodes data into Seigr Cells with HyphaCrypt encryption and integrity verification.
    """

    def __init__(self, segment_id: str, hash_depth: int = 4, use_senary: bool = True):
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

    def encode(self, data: bytes, metadata: dict = None, password: str = None) -> bytes:
        """
        Encodes data and metadata into a Seigr Cell format with encryption and integrity.

        Args:
            data (bytes): Data to encode.
            metadata (dict): Metadata to include in encoding.
            password (str): Optional password for encryption.

        Returns:
            bytes: The encoded and encrypted Seigr Cell.

        Raises:
            ValueError: If encoding or encryption fails.
        """
        logger.debug(f"Encoding data for segment {self.segment_id}")

        # Initialize HyphaCrypt for encryption and integrity
        try:
            hypha = HyphaCrypt(data, self.segment_id, self.hash_depth, self.use_senary)

            # Generate encryption key and encrypt data
            key = hypha.generate_encryption_key(password)
            encrypted_data = hypha.encrypt_data(key)

            # Compute integrity hashes
            primary_hash = hypha.compute_primary_hash()
            hash_tree = hypha.compute_layered_hashes()

            # Prepare CBOR-encoded payload
            seigr_cell_payload = {
                "data": encrypted_data,
                "metadata": metadata or {},
                "primary_hash": primary_hash,
                "hash_tree": hash_tree,
            }
            encoded_cell = cbor_encode(seigr_cell_payload)
            logger.info(f"Seigr Cell encoded for segment {self.segment_id}")

            secure_logger.log_audit_event(
                severity=1,
                category="Encoding",
                message=f"Data encoded into Seigr Cell for segment {self.segment_id}",
                sensitive=False,
            )

            return encoded_cell
        except Exception as e:
            logger.error(f"Failed to encode data for segment {self.segment_id}: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Encoding",
                message=f"Encoding failed for segment {self.segment_id}: {e}",
                sensitive=True,
            )
            raise ValueError("Failed to encode Seigr Cell data")

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

        try:
            # Decode CBOR payload
            payload = cbor_decode(encoded_cell)
            encrypted_data = payload["data"]
            metadata = payload.get("metadata", {})
            primary_hash = payload["primary_hash"]
            hash_tree = payload["hash_tree"]

            logger.info(f"CBOR payload decoded for segment {self.segment_id}")

            # Initialize HyphaCrypt for decryption
            hypha = HyphaCrypt(b"", self.segment_id, self.hash_depth, self.use_senary)

            # Generate decryption key and decrypt data
            key = hypha.generate_encryption_key(password)
            decrypted_data = hypha.decrypt_data(encrypted_data, key)

            # Verify data integrity
            hypha.data = decrypted_data
            verification_results = hypha.verify_integrity(hash_tree)

            if verification_results["status"] != VerificationStatus.VERIFIED:
                logger.warning(
                    f"Integrity verification failed for segment {self.segment_id}"
                )
                secure_logger.log_audit_event(
                    severity=3,
                    category="Decoding",
                    message=f"Integrity verification failed for segment {self.segment_id}",
                    sensitive=True,
                )
                raise ValueError("Data integrity verification failed.")

            logger.info(f"Seigr Cell decoded and verified for segment {self.segment_id}")
            secure_logger.log_audit_event(
                severity=1,
                category="Decoding",
                message=f"Data successfully decoded for segment {self.segment_id}",
                sensitive=False,
            )

            return decrypted_data, metadata
        except Exception as e:
            logger.error(f"Failed to decode Seigr Cell for segment {self.segment_id}: {e}")
            secure_logger.log_audit_event(
                severity=4,
                category="Decoding",
                message=f"Decoding failed for segment {self.segment_id}: {e}",
                sensitive=True,
            )
            raise ValueError("Failed to decode Seigr Cell")
