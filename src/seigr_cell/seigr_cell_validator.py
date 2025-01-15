from datetime import datetime
from typing import Dict

from src.crypto.integrity_verification import (
    verify_hierarchical_integrity,
    verify_integrity,
)
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
    ErrorSeverity,
)
from src.seigr_cell.utils.validation_utils import (
    validate_uuid,
    validate_timestamp,
    MetadataValidationError,
    AccessPolicyValidationError,
)


class SeigrCellValidator:
    """
    Validates Seigr Cells for structural integrity, metadata correctness, and hierarchical hash conformity.
    """

    def __init__(self):
        """
        Initializes the SeigrCellValidator.
        """
        secure_logger.log_audit_event(
            severity=1,
            category="Initialization",
            message="Initialized SeigrCellValidator.",
            sensitive=False,
        )

    def validate(self, encoded_cell: bytes) -> bool:
        """
        Validates the overall structure and integrity of a Seigr Cell.

        Args:
            encoded_cell (bytes): The encoded Seigr Cell to validate.

        Returns:
            bool: True if the Seigr Cell is valid, False otherwise.
        """
        try:
            payload = self._decode_cell_payload(encoded_cell)

            # Validate individual components
            data = payload.get("data")
            if not self._validate_primary_hash(data, payload.get("primary_hash")):
                return False

            if not self._validate_hierarchical_hash(data, payload.get("hash_tree")):
                return False

            if not self._validate_metadata_structure(payload.get("metadata", {})):
                return False

            secure_logger.log_audit_event(
                severity=1,
                category="Validation",
                message="Seigr Cell validated successfully.",
                sensitive=False,
            )
            return True

        except Exception as e:
            self._log_error("cell_validation_fail", "Failed to validate Seigr Cell", e)
            return False

    # ======================
    # Hash Validation
    # ======================

    def _validate_primary_hash(self, data: bytes, primary_hash: str) -> bool:
        """
        Validates the primary integrity hash of the cell data.

        Args:
            data (bytes): The cell's data to verify.
            primary_hash (str): The expected primary hash to match.

        Returns:
            bool: True if primary hash is valid, False otherwise.
        """
        if not primary_hash:
            secure_logger.log_audit_event(
                severity=2,
                category="Validation",
                message="Primary hash missing from Seigr Cell.",
                sensitive=False,
            )
            return False

        is_valid = verify_integrity(data, primary_hash)
        secure_logger.log_audit_event(
            severity=1 if is_valid else 3,
            category="Validation",
            message=f"Primary hash validation result: {'Valid' if is_valid else 'Invalid'}.",
            sensitive=False,
        )
        return is_valid

    def _validate_hierarchical_hash(self, data: bytes, hash_tree: dict) -> bool:
        """
        Validates the hierarchical hash structure of the Seigr Cell.

        Args:
            data (bytes): The cell's data to verify.
            hash_tree (dict): Reference hash tree for hierarchical integrity verification.

        Returns:
            bool: True if the hierarchical hash structure is valid, False otherwise.
        """
        if not hash_tree:
            secure_logger.log_audit_event(
                severity=2,
                category="Validation",
                message="Hash tree missing from Seigr Cell.",
                sensitive=False,
            )
            return False

        is_valid = verify_hierarchical_integrity(data, hash_tree)
        secure_logger.log_audit_event(
            severity=1 if is_valid else 3,
            category="Validation",
            message=f"Hierarchical hash validation result: {'Valid' if is_valid else 'Invalid'}.",
            sensitive=False,
        )
        return is_valid

    # ======================
    # Metadata Validation
    # ======================

    def _validate_metadata_structure(self, metadata: Dict) -> bool:
        """
        Validates the metadata structure.

        Args:
            metadata (dict): Metadata to validate.

        Returns:
            bool: True if metadata structure is valid, False otherwise.
        """
        required_fields = {"cell_id", "timestamp", "version", "lineage"}

        try:
            missing_fields = required_fields - metadata.keys()
            if missing_fields:
                raise MetadataValidationError(f"Metadata missing required fields: {missing_fields}")

            validate_uuid(metadata["cell_id"])
            validate_timestamp(metadata["timestamp"])

            # Validate lineage
            if not self._validate_lineage(metadata.get("lineage", {})):
                raise MetadataValidationError("Invalid lineage structure in metadata.")

            secure_logger.log_audit_event(
                severity=1,
                category="Validation",
                message="Metadata structure validated successfully.",
                sensitive=False,
            )
            return True

        except MetadataValidationError as e:
            secure_logger.log_audit_event(
                severity=3,
                category="Validation",
                message=f"Metadata validation failed: {e}",
                sensitive=True,
            )
            return False

    def _validate_lineage(self, lineage: dict) -> bool:
        """
        Validates the lineage structure in metadata for correct fields and formatting.

        Args:
            lineage (dict): Lineage data within the metadata.

        Returns:
            bool: True if lineage structure is valid, False otherwise.
        """
        required_fields = {"origin", "last_updated"}
        missing_fields = required_fields - lineage.keys()

        if missing_fields:
            secure_logger.log_audit_event(
                severity=2,
                category="Validation",
                message=f"Lineage missing fields: {missing_fields}.",
                sensitive=False,
            )
            return False

        try:
            validate_timestamp(lineage["last_updated"])
            return True
        except MetadataValidationError:
            return False

    # ======================
    # Helper Methods
    # ======================

    def _decode_cell_payload(self, encoded_cell: bytes) -> dict:
        """
        Decodes the payload from an encoded Seigr Cell.

        Args:
            encoded_cell (bytes): The encoded Seigr Cell to decode.

        Returns:
            dict: Decoded payload.
        """
        from src.seigr_cell.seigr_cell_decoder import SeigrCellDecoder

        decoder = SeigrCellDecoder(segment_id="validation")
        _, payload = decoder.decode(encoded_cell)
        return payload

    def _log_error(self, error_id: str, message: str, exception):
        """
        Logs an error.

        Args:
            error_id (str): Unique error identifier.
            message (str): Error message.
            exception: Exception raised.
        """
        error_log = ErrorLogEntry(
            error_id=error_id,
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="SeigrCellValidator",
            message=message,
            details=str(exception),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE,
        )
        secure_logger.log_audit_event(
            severity=4,
            category="Validation",
            message=f"{message}: {exception}",
            sensitive=True,
        )
