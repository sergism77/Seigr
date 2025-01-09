import uuid
from datetime import datetime, timezone

from src.seigr_cell.seigr_cell_encoder import SeigrCellEncoder
from src.seigr_cell.seigr_cell_validator import SeigrCellValidator
from src.seigr_cell.utils.metadata_handler import generate_data_hash, generate_lineage_hash, create_metadata
from src.seigr_cell.utils.integrity_verifier import verify as verify_integrity
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.seigr_cell_pb2 import Metadata


class SeigrCell:
    """
    Core SeigrCell class for securely managing data, metadata, and access policies 
    while ensuring data integrity and compliance with Seigr Ecosystem standards.
    """

    def __init__(
        self,
        segment_id: str,
        data: bytes,
        access_policy: dict = None,
        use_senary: bool = True,
    ):
        """
        Initializes a SeigrCell with specified data, metadata, and configuration.

        Args:
            segment_id (str): Unique identifier for the cell segment.
            data (bytes): Data to be securely stored.
            access_policy (dict): Access control policies.
            use_senary (bool): Flag for senary encoding.
        """
        SeigrCellValidator.validate_initialization(segment_id, data, access_policy)

        self.segment_id = segment_id
        self.data = data
        self.access_policy = access_policy or {}
        self.use_senary = use_senary
        self.cell_id = str(uuid.uuid4())  # Unique identifier for this SeigrCell
        self.metadata = self._generate_metadata()
        self.encoder = SeigrCellEncoder(segment_id, use_senary=use_senary)

        secure_logger.log_audit_event(
            severity=1,
            category="Initialization",
            message=f"SeigrCell initialized with segment ID: {self.segment_id}",
            sensitive=False,
        )

    def _generate_metadata(self) -> Metadata:
        """
        Generates and manages metadata for the SeigrCell.

        Returns:
            Metadata: Populated metadata protobuf.
        """
        try:
            data_hash = generate_data_hash(self.data)
            lineage_hash = generate_lineage_hash(self.cell_id, data_hash)

            metadata = create_metadata(
                cell_id=self.cell_id,
                contributor_id=self.segment_id,
                data_hash=data_hash,
                lineage_hash=lineage_hash,
                access_policy=self.access_policy,
            )

            secure_logger.log_audit_event(
                severity=1,
                category="Metadata",
                message=f"Metadata generated for SeigrCell with segment ID: {self.segment_id}",
                sensitive=False,
            )
            return metadata
        except Exception as e:
            secure_logger.log_audit_event(
                severity=3,
                category="Metadata",
                message=f"Failed to generate metadata for SeigrCell {self.segment_id}: {e}",
                sensitive=True,
            )
            raise

    def store_data(self, password: str = None) -> bytes:
        """
        Encrypts and encodes the data for secure storage.

        Args:
            password (str): Optional encryption password.

        Returns:
            bytes: Encrypted and encoded data.
        """
        try:
            metadata = {
                "access_policy": self.access_policy,
                "creation_timestamp": self.metadata.timestamp,
            }
            encoded_data = self.encoder.encode(
                self.data, metadata=metadata, password=password
            )

            secure_logger.log_audit_event(
                severity=1,
                category="Storage",
                message=f"Data stored in SeigrCell with segment ID: {self.segment_id}",
                sensitive=False,
            )
            return encoded_data

        except Exception as e:
            secure_logger.log_audit_event(
                severity=3,
                category="Storage",
                message=f"Failed to store data in SeigrCell {self.segment_id}: {e}",
                sensitive=True,
            )
            raise

    def retrieve_data(self, encoded_data: bytes, password: str = None) -> bytes:
        """
        Decrypts and retrieves the stored data.

        Args:
            encoded_data (bytes): Encrypted data.
            password (str): Decryption password.

        Returns:
            bytes: Original data.
        """
        try:
            decrypted_data, metadata = self.encoder.decode(
                encoded_data, password=password
            )

            secure_logger.log_audit_event(
                severity=1,
                category="Retrieval",
                message=f"Data retrieved from SeigrCell with segment ID: {self.segment_id}",
                sensitive=False,
            )
            return decrypted_data

        except Exception as e:
            secure_logger.log_audit_event(
                severity=4,
                category="Retrieval",
                message=f"Failed to retrieve data from SeigrCell {self.segment_id}: {e}",
                sensitive=True,
            )
            raise

    def verify_integrity(self, reference_hash_tree: dict) -> bool:
        """
        Verifies the data integrity of the SeigrCell.

        Args:
            reference_hash_tree (dict): Reference hash tree for integrity check.

        Returns:
            bool: True if integrity verification is successful, False otherwise.
        """
        try:
            integrity_status = verify_integrity(self.data, reference_hash_tree)
            if integrity_status:
                secure_logger.log_audit_event(
                    severity=1,
                    category="Integrity",
                    message=f"Integrity verified for SeigrCell {self.segment_id}",
                    sensitive=False,
                )
            else:
                secure_logger.log_audit_event(
                    severity=2,
                    category="Integrity",
                    message=f"Integrity verification failed for SeigrCell {self.segment_id}",
                    sensitive=True,
                )
            return integrity_status

        except Exception as e:
            secure_logger.log_audit_event(
                severity=4,
                category="Integrity",
                message=f"Integrity verification failed with error: {e}",
                sensitive=True,
            )
            raise

    def update_metadata(self, new_access_policy: dict = None):
        """
        Updates SeigrCell metadata dynamically.

        Args:
            new_access_policy (dict): New access policies.
        """
        try:
            if new_access_policy:
                self.access_policy.update(new_access_policy)
                secure_logger.log_audit_event(
                    severity=1,
                    category="Metadata Update",
                    message=f"Access policy updated for SeigrCell {self.segment_id}",
                    sensitive=False,
                )

        except Exception as e:
            secure_logger.log_audit_event(
                severity=3,
                category="Metadata Update",
                message=f"Failed to update metadata for SeigrCell {self.segment_id}: {e}",
                sensitive=True,
            )
            raise
