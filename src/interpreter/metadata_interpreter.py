import logging
from datetime import datetime, timezone
from src.crypto.hash_utils import hypha_hash
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import FileMetadata, SegmentMetadata, AccessControlList

logger = logging.getLogger(__name__)

class MetadataInterpreter:
    """
    Handles parsing, validating, and updating metadata for `.seigr` capsules.
    Ensures metadata compatibility, logs access events, and manages metadata structure.
    """

    def __init__(self, version="1.0"):
        """
        Initializes MetadataInterpreter for managing metadata in `.seigr` capsules.

        Args:
            version (str): Protocol version to enforce (default is "1.0").
        """
        self.version = version
        logger.info(f"MetadataInterpreter initialized for version {version}")

    def parse_and_validate_segment(self, segment_metadata: SegmentMetadata) -> SegmentMetadata:
        """
        Parses and validates metadata for an individual segment.

        Args:
            segment_metadata (SegmentMetadata): Metadata for a single segment.

        Returns:
            SegmentMetadata: Parsed segment metadata if valid, otherwise None.
        """
        if not segment_metadata.segment_hash:
            logger.warning("Segment metadata is missing a hash; validation failed.")
            return None

        # Additional segment validation logic can be added here
        logger.debug(f"Validated segment metadata for segment index {segment_metadata.segment_index}")
        return segment_metadata

    def parse_and_validate_file(self, file_metadata: FileMetadata) -> FileMetadata:
        """
        Parses and validates file-level metadata for a `.seigr` capsule.

        Args:
            file_metadata (FileMetadata): The capsule's file metadata.

        Returns:
            FileMetadata: Parsed and validated file metadata if valid, otherwise None.
        """
        if not self.validate_metadata(file_metadata):
            logger.error("File metadata validation failed.")
            return None
        logger.debug("File metadata validated successfully.")
        return file_metadata

    def validate_metadata(self, metadata: FileMetadata) -> bool:
        """
        Validates that the metadata conforms to the required structure and version compatibility.

        Args:
            metadata (FileMetadata): The metadata object to validate.

        Returns:
            bool: True if metadata is valid, False otherwise.
        """
        if metadata.version != self.version:
            logger.warning(f"Metadata version mismatch: expected {self.version}, got {metadata.version}")
            return False
        if not metadata.file_hash:
            logger.warning("File metadata is missing a file hash.")
            return False
        logger.info("Metadata validated successfully.")
        return True

    def update_access_log(self, metadata: FileMetadata, hyphen_id: str):
        """
        Updates the access log in metadata, tracking access events and hyphen IDs.

        Args:
            metadata (FileMetadata): Metadata to update.
            hyphen_id (str): ID of the accessing entity.
        """
        if not metadata.HasField("access_control_list"):
            metadata.access_control_list.CopyFrom(AccessControlList(entries=[]))

        access_count = metadata.access_control_list.access_count
        metadata.access_control_list.access_count = access_count + 1
        metadata.access_control_list.last_accessed = datetime.now(timezone.utc).isoformat()
        metadata.access_control_list.hyphen_access_history.append(hyphen_id)

        logger.info(f"Access logged for hyphen {hyphen_id}; updated access count: {access_count + 1}")

    def compute_integrity_hash(self, metadata: FileMetadata) -> str:
        """
        Computes an integrity hash for the metadata.

        Args:
            metadata (FileMetadata): The metadata object for which to compute the hash.

        Returns:
            str: Integrity hash for the metadata.
        """
        data_to_hash = f"{metadata.version}{metadata.file_hash}{metadata.creation_timestamp}".encode("utf-8")
        integrity_hash = hypha_hash(data_to_hash)
        logger.debug(f"Computed integrity hash: {integrity_hash}")
        return integrity_hash

    def validate_integrity(self, metadata: FileMetadata, expected_hash: str) -> bool:
        """
        Validates the integrity of the metadata by comparing against an expected hash.

        Args:
            metadata (FileMetadata): Metadata object to validate.
            expected_hash (str): Expected integrity hash.

        Returns:
            bool: True if integrity is validated, False otherwise.
        """
        computed_hash = self.compute_integrity_hash(metadata)
        if computed_hash == expected_hash:
            logger.info("Integrity validated successfully.")
            return True
        else:
            logger.error(f"Integrity validation failed: expected {expected_hash}, got {computed_hash}")
            return False

    def extend_capabilities(self, metadata_version: str):
        """
        Enables additional features based on metadata version compatibility.

        Args:
            metadata_version (str): The version of metadata to enable extensions for.
        """
        # Example: Future protocol extensions could be added here based on version
        if metadata_version == "1.1":
            logger.info("Activated extended capabilities for metadata version 1.1.")
        else:
            logger.debug(f"No extensions applied for metadata version {metadata_version}")

    def verify_access_permissions(self, acl: AccessControlList, user_id: str, required_permission: str) -> bool:
        """
        Checks if a user has the required permissions based on the access control list.

        Args:
            acl (AccessControlList): The ACL to verify.
            user_id (str): The ID of the user requesting access.
            required_permission (str): The permission needed for access.

        Returns:
            bool: True if access is granted, False otherwise.
        """
        for entry in acl.entries:
            if entry.user_id == user_id and required_permission in entry.permissions:
                logger.debug(f"Access granted for user {user_id} with permission {required_permission}")
                return True
        logger.warning(f"Access denied for user {user_id} (required permission: {required_permission})")
        return False
