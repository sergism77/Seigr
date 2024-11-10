import logging
from src.crypto.hash_utils import hypha_hash
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata, LineageEntry, FileMetadata, AccessControlList, TriggerEvent

logger = logging.getLogger(__name__)

def verify_integrity(stored_hash: str, senary_data: str) -> bool:
    """
    Verifies the integrity of the .seigr file by comparing the stored hash with a computed hash from senary data.

    Args:
        stored_hash (str): The expected hash value stored for the .seigr file.
        senary_data (str): Senary-encoded data to compute the hash for verification.

    Returns:
        bool: True if the computed hash matches the stored hash, False otherwise.
    """
    computed_hash = hypha_hash(senary_data.encode())
    valid = computed_hash == stored_hash

    if valid:
        logger.info(f"Global integrity check passed for .seigr file. Hash: {stored_hash}")
    else:
        logger.warning(f"Global integrity check failed. Expected: {stored_hash}, Got: {computed_hash}")

    return valid

def verify_segment_integrity(segment_metadata: SegmentMetadata, data: bytes) -> bool:
    """
    Verifies the integrity of a .seigr file segment by comparing computed data hash with stored `data_hash`.

    Args:
        segment_metadata (SegmentMetadata): A protobuf SegmentMetadata message containing segment details.
        data (bytes): Actual data of the segment for hash comparison.

    Returns:
        bool: True if integrity check for the segment passes, False otherwise.
    """
    if not isinstance(segment_metadata, SegmentMetadata):
        raise TypeError("segment_metadata must be an instance of SegmentMetadata")

    computed_data_hash = hypha_hash(data)

    if computed_data_hash != segment_metadata.data_hash:
        logger.warning(f"Integrity check failed for segment '{segment_metadata.segment_hash}'. "
                       f"Expected data hash: {segment_metadata.data_hash}, Got: {computed_data_hash}")
        return False
    
    logger.info(f"Integrity check passed for segment '{segment_metadata.segment_hash}'.")
    return True

def verify_full_lineage_integrity(lineage_entries: list[LineageEntry]) -> bool:
    """
    Verifies the integrity of the lineage by ensuring continuity of hashes across entries.

    Args:
        lineage_entries (list[LineageEntry]): A list of Protobuf LineageEntry objects representing the lineage.

    Returns:
        bool: True if the lineage maintains hash continuity, False otherwise.
    """
    all_entries_valid = True

    for i, entry in enumerate(lineage_entries):
        entry_hash = entry.hash
        previous_hash = entry.previous_hash or ""
        data = entry.data

        expected_hash = hypha_hash(f"{previous_hash}{data}".encode())

        if entry_hash != expected_hash:
            logger.error(f"Integrity check failed for lineage entry {i}. Expected hash: {expected_hash}, "
                         f"Stored hash: {entry_hash}")
            all_entries_valid = False
        else:
            logger.debug(f"Integrity check passed for lineage entry {i}. Hash: {entry_hash}")

    if all_entries_valid:
        logger.info("Full lineage integrity check passed.")
    else:
        logger.warning("Full lineage integrity check failed. Discrepancies found in one or more entries.")

    return all_entries_valid

def verify_file_metadata_integrity(file_metadata: FileMetadata) -> bool:
    """
    Verifies the integrity of the file metadata by checking the hash of all segments against the stored file hash.

    Args:
        file_metadata (FileMetadata): A Protobuf FileMetadata object containing file-level metadata.

    Returns:
        bool: True if the computed hash matches the stored file hash.
    """
    combined_segment_hashes = "".join([segment.segment_hash for segment in file_metadata.segments])
    computed_file_hash = hypha_hash(combined_segment_hashes.encode())

    if file_metadata.file_hash == computed_file_hash:
        logger.info("File metadata integrity check passed.")
        return True
    else:
        logger.warning(f"File metadata integrity check failed. Expected: {file_metadata.file_hash}, "
                       f"Got: {computed_file_hash}")
        return False

def verify_partial_lineage(lineage_entries: list[LineageEntry], depth: int) -> bool:
    """
    Verifies the integrity of a subset of the lineage, up to a specified depth.

    Args:
        lineage_entries (list[LineageEntry]): A list of Protobuf LineageEntry objects.
        depth (int): The depth up to which integrity should be verified.

    Returns:
        bool: True if integrity is verified up to the specified depth, False otherwise.
    """
    for i in range(min(depth, len(lineage_entries))):
        entry = lineage_entries[i]
        entry_hash = entry.hash
        previous_hash = entry.previous_hash or ""
        data = entry.data

        expected_hash = hypha_hash(f"{previous_hash}{data}".encode())
        
        if entry_hash != expected_hash:
            logger.error(f"Partial integrity check failed at entry {i}. Expected: {expected_hash}, Stored: {entry_hash}")
            return False
        logger.debug(f"Partial integrity check passed for entry {i}")

    logger.info(f"Partial lineage integrity verified up to depth {depth}")
    return True

def verify_checksum(data: bytes, stored_checksum: str) -> bool:
    """
    Verifies the checksum for an entire .seigr file structure.

    Args:
        data (bytes): Binary data of the entire file.
        stored_checksum (str): The expected checksum stored in metadata.

    Returns:
        bool: True if checksum matches, False otherwise.
    """
    computed_checksum = hypha_hash(data)
    if computed_checksum == stored_checksum:
        logger.info("Checksum verification passed for the .seigr file.")
        return True
    else:
        logger.warning(f"Checksum verification failed. Expected: {stored_checksum}, Got: {computed_checksum}")
        return False

def validate_acl_for_integrity_check(acl: AccessControlList, user_id: str) -> bool:
    """
    Validates whether a user has permission to perform integrity checks based on ACL.

    Args:
        acl (AccessControlList): Access control list to verify permissions.
        user_id (str): ID of the user requesting the integrity check.

    Returns:
        bool: True if user has permission, False otherwise.
    """
    for entry in acl.entries:
        if entry.user_id == user_id and "verify_integrity" in entry.permissions:
            logger.debug(f"User {user_id} has permission to perform integrity checks.")
            return True
    logger.warning(f"User {user_id} lacks permission to perform integrity checks.")
    return False

def reverify_on_event(event_type: TriggerEvent, data: bytes, stored_hash: str) -> bool:
    """
    Re-verifies integrity based on specific events, such as data change or integrity failure.

    Args:
        event_type (TriggerEvent): The event that triggers re-verification.
        data (bytes): Data to verify if needed.
        stored_hash (str): Expected hash or checksum.

    Returns:
        bool: True if re-verification passes, False otherwise.
    """
    logger.debug(f"Triggered re-verification for event: {event_type}")
    if event_type == TriggerEvent.ON_DATA_CHANGE or event_type == TriggerEvent.ON_INTEGRITY_FAILURE:
        return verify_checksum(data, stored_hash)
    return True
