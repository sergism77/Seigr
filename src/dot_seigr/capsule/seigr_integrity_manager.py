import time
from src.crypto.hash_utils import hypha_hash
from src.logger.secure_logger import secure_logger


class IntegrityManager:
    """
    Manages data integrity checks and validation for Seigr capsules,
    supporting multi-level hashing, snapshots, and detailed validation logging.
    """

    def __init__(self, data: bytes, hypha_crypt, hash_mode: str = "SHA-256"):
        """
        Initializes the IntegrityManager with data and cryptographic hashing.

        Args:
            data (bytes): The data to compute integrity against.
            hypha_crypt (HyphaCrypt): Instance of HyphaCrypt for cryptographic operations.
            hash_mode (str): Hash mode for integrity checks (default is "SHA-256").
        """
        self.data = data
        self.hypha_crypt = hypha_crypt
        self.hash_mode = hash_mode
        self.checksum = None  # Stores the primary checksum for validation

        secure_logger.log_audit_event(
            severity="info",
            category="Integrity",
            message=f"IntegrityManager initialized with hash mode {hash_mode}.",
        )

    def compute_integrity(self, metadata: dict) -> str:
        """
        Computes a comprehensive integrity checksum based on data and metadata.

        Args:
            metadata (dict): Metadata including segment and file-level hashes.

        Returns:
            str: Calculated integrity checksum.
        """
        segment_hash = metadata.get("segment_hash", "")
        metadata_hash = hypha_hash(segment_hash.encode() + hypha_hash(self.data).encode())
        self.checksum = hypha_hash(metadata_hash.encode())

        secure_logger.log_audit_event(
            severity="info",
            category="Integrity",
            message=f"Computed integrity checksum: {self.checksum}.",
        )
        return self.checksum

    def validate_integrity(self, reference_checksum: str, metadata: dict) -> bool:
        """
        Validates the current data against a reference checksum.

        Args:
            reference_checksum (str): Known, correct checksum for verification.
            metadata (dict): Metadata to compute integrity and compare.

        Returns:
            bool: True if validation is successful, False otherwise.
        """
        computed_checksum = self.compute_integrity(metadata)
        is_valid = computed_checksum == reference_checksum

        if is_valid:
            secure_logger.log_audit_event(
                severity="info",
                category="Integrity",
                message="Integrity validation successful.",
            )
        else:
            secure_logger.log_audit_event(
                severity="error",
                category="Integrity",
                message=f"Integrity validation failed. Expected {reference_checksum}, got {computed_checksum}.",
            )
        return is_valid

    def snapshot_integrity(self, metadata: dict) -> dict:
        """
        Captures a snapshot of current integrity details, including metadata and checksum.

        Args:
            metadata (dict): Metadata to snapshot along with integrity checksum.

        Returns:
            dict: Snapshot containing metadata, checksum, and timestamp.
        """
        timestamp = int(time.time())
        snapshot = {
            "metadata": metadata,
            "checksum": self.compute_integrity(metadata),
            "timestamp": timestamp,
        }

        secure_logger.log_audit_event(
            severity="info",
            category="Integrity",
            message=f"Integrity snapshot taken at {timestamp} with checksum {snapshot['checksum']}.",
        )
        return snapshot

    def recompute_data_hash(self) -> str:
        """
        Recomputes the data hash and updates internal checksum based on current data.

        Returns:
            str: Updated data hash.
        """
        self.checksum = hypha_hash(self.data)

        secure_logger.log_audit_event(
            severity="debug",
            category="Integrity",
            message=f"Recomputed data hash: {self.checksum}.",
        )
        return self.checksum

    def set_data(self, new_data: bytes):
        """
        Updates data managed by IntegrityManager and resets checksum for recalculation.

        Args:
            new_data (bytes): New data to manage for integrity checks.
        """
        self.data = new_data
        self.checksum = None  # Reset checksum to force recalculation

        secure_logger.log_audit_event(
            severity="debug",
            category="Integrity",
            message="Data updated for integrity management; checksum reset.",
        )

    def enable_detailed_logging(self, enable: bool = True):
        """
        Enables or disables detailed logging for integrity operations.

        Args:
            enable (bool): Whether to enable detailed logging (default is True).
        """
        level = "debug" if enable else "info"

        secure_logger.log_audit_event(
            severity=level,
            category="Integrity",
            message=f"Detailed logging {'enabled' if enable else 'disabled'} for IntegrityManager.",
        )
