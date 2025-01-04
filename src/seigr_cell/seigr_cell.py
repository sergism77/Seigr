import hashlib
import logging
import uuid
from datetime import datetime, timezone

from src.crypto.integrity_verification import verify_integrity
from src.seigr_cell.seigr_cell_encoder import SeigrCellEncoder
from src.seigr_protocol.compiled.seigr_cell_pb2 import (
    Metadata,
    SeigrCell,
)

# Initialize logger
logger = logging.getLogger(__name__)


class SeigrCell:
    def __init__(
        self,
        segment_id: str,
        data: bytes,
        access_policy: dict = None,
        use_senary: bool = True,
    ):
        """
        Initializes a SeigrCell with specified data and metadata.

        Args:
            segment_id (str): Unique identifier for the cell segment.
            data (bytes): The primary data to be stored in the cell.
            access_policy (dict): Access policy metadata.
            use_senary (bool): Whether to use senary encoding for integrity verification.
        """
        self.segment_id = segment_id
        self.data = data
        self.access_policy = access_policy or {}
        self.use_senary = use_senary
        self.cell_id = str(uuid.uuid4())  # Unique identifier for this SeigrCell
        self.metadata = self._generate_metadata()
        self.encoder = SeigrCellEncoder(segment_id, use_senary=use_senary)
        logger.info(f"Initialized SeigrCell with segment ID {self.segment_id}")

    def _generate_metadata(self) -> Metadata:
        """
        Generates metadata for the SeigrCell, including timestamps, unique ID, and access policies.

        Returns:
            Metadata: Populated metadata protobuf.
        """
        # Calculate data hash for integrity tracking
        data_hash = hashlib.sha256(self.data).hexdigest()

        # Generate lineage hash based on versioning and lineage context
        lineage_hash = hashlib.sha256((self.cell_id + data_hash).encode()).hexdigest()

        metadata = Metadata(
            cell_id=self.cell_id,
            contributor_id=self.segment_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            version="1.0",  # Set version; this could also be dynamically updated
            data_hash=data_hash,
            lineage_hash=lineage_hash,
            access_level=self.access_policy.get(
                "level", "public"
            ),  # e.g., "public", "restricted"
            tags=self.access_policy.get("tags", ["initial", "seigr-cell"]),
        )

        logger.debug(
            f"Generated metadata for segment {self.segment_id} with cell ID {self.cell_id}"
        )
        return metadata

    def store_data(self, password: str = None) -> bytes:
        """
        Stores the cell data with encryption and encoding.

        Args:
            password (str): Optional password for data encryption.

        Returns:
            bytes: The encoded and encrypted cell data.
        """
        metadata = {
            "access_policy": self.access_policy,
            "creation_timestamp": self.metadata.timestamp,
        }
        encoded_data = self.encoder.encode(
            self.data, metadata=metadata, password=password
        )
        logger.info(f"Data stored in SeigrCell with segment ID {self.segment_id}")
        return encoded_data

    def retrieve_data(self, encoded_data: bytes, password: str = None) -> bytes:
        """
        Retrieves and decrypts the data stored in the SeigrCell.

        Args:
            encoded_data (bytes): The encoded and encrypted cell data.
            password (str): Optional password for decryption.

        Returns:
            bytes: The original decrypted data.
        """
        try:
            decrypted_data, metadata = self.encoder.decode(
                encoded_data, password=password
            )
            logger.info(
                f"Data retrieved for SeigrCell with segment ID {self.segment_id}"
            )
            return decrypted_data
        except ValueError as e:
            logger.error(f"Failed to retrieve data for segment {self.segment_id}: {e}")
            raise

    def verify_integrity(self, reference_hash_tree: dict) -> bool:
        """
        Verifies the integrity of the SeigrCell data.

        Args:
            reference_hash_tree (dict): Reference hash hierarchy for integrity verification.

        Returns:
            bool: True if integrity verification is successful, False otherwise.
        """
        integrity_status = verify_integrity(self.data, reference_hash_tree)
        if integrity_status:
            logger.info(f"Integrity verified for SeigrCell {self.segment_id}")
        else:
            logger.warning(
                f"Integrity verification failed for SeigrCell {self.segment_id}"
            )
        return integrity_status

    def update_metadata(self, new_access_policy: dict = None):
        """
        Updates the metadata of the SeigrCell, primarily for updating access policies.

        Args:
            new_access_policy (dict): New access policy to update.
        """
        if new_access_policy:
            self.metadata.access_level = new_access_policy.get(
                "level", self.metadata.access_level
            )
            self.metadata.tags.extend(new_access_policy.get("tags", []))
            logger.info(f"Access policy updated for SeigrCell {self.segment_id}")
