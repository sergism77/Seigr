import uuid
from src.seigr_cell.seigr_cell_encoder import SeigrCellEncoder
from src.seigr_cell.seigr_cell_validator import SeigrCellValidator
from src.seigr_cell.seigr_cell_metadata import SeigrCellMetadata
from src.logger.secure_logger import secure_logger


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
        self.access_policy = access_policy or {"level": "public", "tags": []}
        self.use_senary = use_senary
        self.cell_id = str(uuid.uuid4())  # Unique identifier for this SeigrCell

        self.metadata_manager = SeigrCellMetadata(segment_id=segment_id)
        self.metadata = self.metadata_manager.generate_metadata(data, self.access_policy)
        self.encoder = SeigrCellEncoder(segment_id, use_senary=use_senary)

        secure_logger.log_audit_event(
            severity=1,
            category="Initialization",
            message=f"SeigrCell initialized with segment ID: {self.segment_id}",
            sensitive=False,
        )

    def store_data(self, password: str = None) -> bytes:
        """
        Encrypts and encodes the data for secure storage.

        Args:
            password (str): Optional encryption password.

        Returns:
            bytes: Encrypted and encoded data.
        """
        try:
            encoded_data = self.encoder.encode(
                self.data,
                metadata=self.metadata_manager.serialize_metadata(self.metadata),
                password=password,
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
            decrypted_data, serialized_metadata = self.encoder.decode(
                encoded_data, password=password
            )
            self.metadata = self.metadata_manager.deserialize_metadata(serialized_metadata)

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


    def update_access_policy(self, new_policy: dict):
        """
        Updates SeigrCell access policy dynamically.

        Args:
            new_policy (dict): New access control policies.
        """
        try:
            self.metadata["access_level"] = new_policy.get("level", self.metadata["access_level"])
            self.metadata["tags"] = new_policy.get("tags", self.metadata["tags"])
            self.metadata_manager.update_metadata(self.metadata, {"access_policy": new_policy})

            secure_logger.log_audit_event(
                severity=1,
                category="Access Policy Update",
                message=f"Access policy updated for SeigrCell {self.segment_id}",
                sensitive=False,
            )
        except Exception as e:
            secure_logger.log_audit_event(
                severity=3,
                category="Access Policy Update",
                message=f"Failed to update access policy for SeigrCell {self.segment_id}: {e}",
                sensitive=True,
            )
            raise
