from src.crypto.hash_utils import hypha_hash
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import (
    AccessControlList,
    FileMetadata,
    LineageEntry,
    SegmentMetadata,
    TriggerEvent,
)


def compute_hash(data: bytes) -> str:
    """
    Computes a cryptographic hash for the provided data.

    Args:
        data (bytes): The data to hash.

    Returns:
        str: The computed hash as a hexadecimal string.
    """
    return hypha_hash(data)


def verify_integrity(stored_hash: str, senary_data: str) -> bool:
    """
    Verifies the integrity of a `.seigr` file by comparing the stored hash with a computed hash.

    Args:
        stored_hash (str): The expected hash stored for the `.seigr` file.
        senary_data (str): Senary-encoded data to compute the hash for verification.

    Returns:
        bool: True if the computed hash matches the stored hash, False otherwise.
    """
    computed_hash = compute_hash(senary_data.encode())

    if computed_hash == stored_hash:
        secure_logger.log_audit_event(
            "info", "Integrity", f"Global integrity check passed. Hash: {stored_hash}"
        )
        return True
    else:
        secure_logger.log_audit_event(
            "warning",
            "Integrity",
            f"Integrity check failed. Expected: {stored_hash}, Got: {computed_hash}",
        )
        return False


def verify_segment_integrity(segment_metadata: SegmentMetadata, data: bytes) -> bool:
    """
    Verifies the integrity of a `.seigr` file segment by comparing computed data hash with stored hash.

    Args:
        segment_metadata (SegmentMetadata): Metadata containing segment integrity details.
        data (bytes): Actual segment data for hash comparison.

    Returns:
        bool: True if integrity check for the segment passes, False otherwise.
    """
    computed_data_hash = compute_hash(data)

    if computed_data_hash == segment_metadata.data_hash:
        secure_logger.log_audit_event(
            "info",
            "Integrity",
            f"Integrity check passed for segment {segment_metadata.segment_hash}.",
        )
        return True
    else:
        secure_logger.log_audit_event(
            "error",
            "Integrity",
            f"Integrity check failed for segment {segment_metadata.segment_hash}. Expected: {segment_metadata.data_hash}, Got: {computed_data_hash}.",
        )
        return False


def verify_lineage_continuity(lineage_entries: list[LineageEntry]) -> bool:
    """
    Verifies continuity of hashes across lineage entries to ensure historical integrity.

    Args:
        lineage_entries (list[LineageEntry]): List of lineage entries representing the file’s history.

    Returns:
        bool: True if the lineage maintains hash continuity, False otherwise.
    """
    all_entries_valid = True

    for i, entry in enumerate(lineage_entries):
        expected_hash = compute_hash(f"{entry.previous_hash or ''}{entry.data}".encode())

        if entry.hash != expected_hash:
            secure_logger.log_audit_event(
                "error",
                "Integrity",
                f"Lineage check failed at entry {i}. Expected: {expected_hash}, Stored: {entry.hash}.",
            )
            all_entries_valid = False
        else:
            secure_logger.log_audit_event(
                "debug", "Integrity", f"Integrity check passed for lineage entry {i}."
            )

    if all_entries_valid:
        secure_logger.log_audit_event("info", "Integrity", "Lineage integrity check passed.")
    else:
        secure_logger.log_audit_event(
            "warning", "Integrity", "Lineage integrity check failed. Discrepancies found."
        )

    return all_entries_valid


def verify_file_metadata_integrity(file_metadata: FileMetadata) -> bool:
    """
    Verifies integrity of file metadata by checking the hash of all segments against the stored file hash.

    Args:
        file_metadata (FileMetadata): Metadata containing file-level integrity details.

    Returns:
        bool: True if the computed hash matches the stored file hash, False otherwise.
    """
    combined_segment_hashes = "".join([segment.segment_hash for segment in file_metadata.segments])
    computed_file_hash = compute_hash(combined_segment_hashes.encode())

    if computed_file_hash == file_metadata.file_hash:
        secure_logger.log_audit_event("info", "Integrity", "File metadata integrity check passed.")
        return True
    else:
        secure_logger.log_audit_event(
            "warning",
            "Integrity",
            f"File metadata integrity check failed. Expected: {file_metadata.file_hash}, Got: {computed_file_hash}.",
        )
        return False


def verify_partial_lineage(lineage_entries: list[LineageEntry], depth: int) -> bool:
    """
    Verifies integrity of a subset of the lineage up to a specified depth.

    Args:
        lineage_entries (list[LineageEntry]): List of lineage entries.
        depth (int): Depth up to which integrity should be verified.

    Returns:
        bool: True if integrity is verified up to the specified depth, False otherwise.
    """
    for i in range(min(depth, len(lineage_entries))):
        entry = lineage_entries[i]
        expected_hash = compute_hash(f"{entry.previous_hash or ''}{entry.data}".encode())

        if entry.hash != expected_hash:
            secure_logger.log_audit_event(
                "error",
                "Integrity",
                f"Partial integrity check failed at entry {i}. Expected: {expected_hash}, Stored: {entry.hash}.",
            )
            return False
        secure_logger.log_audit_event(
            "debug", "Integrity", f"Partial integrity check passed for entry {i}."
        )

    secure_logger.log_audit_event(
        "info", "Integrity", f"Partial lineage integrity verified up to depth {depth}."
    )
    return True


def verify_checksum(data: bytes, stored_checksum: str) -> bool:
    """
    Verifies checksum for an entire `.seigr` file structure.

    Args:
        data (bytes): Binary data of the entire file.
        stored_checksum (str): Expected checksum stored in metadata.

    Returns:
        bool: True if checksum matches, False otherwise.
    """
    computed_checksum = compute_hash(data)

    if computed_checksum == stored_checksum:
        secure_logger.log_audit_event(
            "info", "Integrity", "Checksum verification passed for the .seigr file."
        )
        return True
    else:
        secure_logger.log_audit_event(
            "warning",
            "Integrity",
            f"Checksum verification failed. Expected: {stored_checksum}, Got: {computed_checksum}.",
        )
        return False


def validate_acl_for_integrity_check(acl: AccessControlList, user_id: str) -> bool:
    """
    Checks if a user has permission to perform integrity checks based on ACL.

    Args:
        acl (AccessControlList): Access control list defining permissions.
        user_id (str): ID of the user requesting the integrity check.

    Returns:
        bool: True if user has permission, False otherwise.
    """
    for entry in acl.entries:
        if entry.user_id == user_id and "verify_integrity" in entry.permissions:
            secure_logger.log_audit_event(
                "debug", "ACL", f"User {user_id} has permission to perform integrity checks."
            )
            return True

    secure_logger.log_audit_event(
        "warning", "ACL", f"User {user_id} lacks permission to perform integrity checks."
    )
    return False


def reverify_on_event(event_type: TriggerEvent, data: bytes, stored_hash: str) -> bool:
    """
    Re-verifies integrity based on specific trigger events.

    Args:
        event_type (TriggerEvent): The event type triggering re-verification.
        data (bytes): Data to verify.
        stored_hash (str): Expected hash or checksum.

    Returns:
        bool: True if re-verification passes, False otherwise.
    """
    secure_logger.log_audit_event(
        "debug", "Integrity", f"Triggered re-verification for event: {event_type}."
    )

    if event_type in {TriggerEvent.ON_DATA_CHANGE, TriggerEvent.ON_INTEGRITY_FAILURE}:
        return verify_checksum(data, stored_hash)

    return True
