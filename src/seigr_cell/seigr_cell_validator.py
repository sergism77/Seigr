# src/seigr_cell/seigr_cell_validator.py

from datetime import datetime

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
            primary_hash = payload.get("primary_hash")
            hash_tree = payload.get("hash_tree")
            data = payload.get("data")

            # Verify primary integrity hash and hierarchical hash tree
            if not self._validate_primary_hash(data, primary_hash):
                secure_logger.log_audit_event(
                    severity=3,
                    category="Validation",
                    message="Primary hash validation failed.",
                    sensitive=False,
                )
                return False

            if not self._validate_hierarchical_hash(data, hash_tree):
                secure_logger.log_audit_event(
                    severity=3,
                    category="Validation",
                    message="Hierarchical hash validation failed.",
                    sensitive=False,
                )
                return False

            # Validate metadata structure and essential fields
            if not self._validate_metadata_structure(payload.get("metadata", {})):
                secure_logger.log_audit_event(
                    severity=3,
                    category="Validation",
                    message="Metadata structure validation failed.",
                    sensitive=False,
                )
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

    def _validate_primary_hash(self, data: bytes, primary_hash: str) -> bool:
        """
        Validates the primary integrity hash of the cell data.

        Args:
            data (bytes): The cell's data to verify.
            primary_hash (str): The expected primary hash to match.

        Returns:
            bool: True if primary hash is valid, False otherwise.
        """
        if primary_hash is None:
            secure_logger.log_audit_event(
                severity=2,
                category="Validation",
                message="Primary hash missing from Seigr Cell.",
                sensitive=False,
            )
            return False

        valid = verify_integrity(data, primary_hash)
        secure_logger.log_audit_event(
            severity=1 if valid else 2,
            category="Validation",
            message=f"Primary hash verification result: {'Valid' if valid else 'Invalid'}.",
            sensitive=False,
        )
        return valid

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

        valid = verify_hierarchical_integrity(data, hash_tree)
        secure_logger.log_audit_event(
            severity=1 if valid else 2,
            category="Validation",
            message=f"Hierarchical hash verification result: {'Valid' if valid else 'Invalid'}.",
            sensitive=False,
        )
        return valid

    def _validate_metadata_structure(self, metadata: dict) -> bool:
        """
        Checks that metadata contains required fields and conforms to expected structure.

        Args:
            metadata (dict): Metadata to validate.

        Returns:
            bool: True if metadata structure is valid, False otherwise.
        """
        required_fields = {"created_at", "cell_id", "version", "status", "lineage"}

        missing_fields = required_fields - metadata.keys()
        if missing_fields:
            secure_logger.log_audit_event(
                severity=2,
                category="Validation",
                message=f"Metadata missing required fields: {missing_fields}.",
                sensitive=False,
            )
            return False

        # Additional field checks
        if not self._validate_lineage(metadata.get("lineage", {})):
            secure_logger.log_audit_event(
                severity=2,
                category="Validation",
                message="Lineage structure in metadata is invalid.",
                sensitive=False,
            )
            return False

        if not isinstance(metadata.get("version"), str) or not metadata.get("version"):
            secure_logger.log_audit_event(
                severity=2,
                category="Validation",
                message="Version format in metadata is invalid.",
                sensitive=False,
            )
            return False

        secure_logger.log_audit_event(
            severity=1,
            category="Validation",
            message="Metadata structure validated successfully.",
            sensitive=False,
        )
        return True

    def _validate_lineage(self, lineage: dict) -> bool:
        """
        Validates the lineage structure in metadata for correct fields and formatting.

        Args:
            lineage (dict): Lineage data within the metadata.

        Returns:
            bool: True if lineage structure is valid, False otherwise.
        """
        required_lineage_fields = {"origin", "last_updated"}

        missing_lineage_fields = required_lineage_fields - lineage.keys()
        if missing_lineage_fields:
            secure_logger.log_audit_event(
                severity=2,
                category="Validation",
                message=f"Lineage is missing required fields: {missing_lineage_fields}.",
                sensitive=False,
            )
            return False

        # Check timestamp format for 'last_updated'
        try:
            datetime.fromisoformat(lineage["last_updated"])
        except (ValueError, KeyError):
            secure_logger.log_audit_event(
                severity=2,
                category="Validation",
                message="Lineage 'last_updated' field is improperly formatted.",
                sensitive=False,
            )
            return False

        return True

    def _decode_cell_payload(self, encoded_cell: bytes) -> dict:
        """
        Decodes the payload from an encoded Seigr Cell to access its contents.

        Args:
            encoded_cell (bytes): The encoded Seigr Cell to decode.

        Returns:
            dict: Decoded payload including data, metadata, and hash information.
        """
        from src.seigr_cell.seigr_cell_decoder import SeigrCellDecoder

        decoder = SeigrCellDecoder(segment_id="validation")
        _, payload = decoder.decode(encoded_cell)

        secure_logger.log_audit_event(
            severity=1,
            category="Validation",
            message="Decoded Seigr Cell payload for validation.",
            sensitive=False,
        )
        return payload

    def _log_error(self, error_id: str, message: str, exception):
        """
        Logs a structured error for validation failures.

        Args:
            error_id (str): Unique identifier for the error.
            message (str): Descriptive error message.
            exception: The exception raised during the error.
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
