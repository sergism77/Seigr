import logging
from src.crypto.hash_utils import hypha_hash
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata, LineageEntry, FileMetadata

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
    # Ensure segment_metadata is of the correct type
    if not isinstance(segment_metadata, SegmentMetadata):
        raise TypeError("segment_metadata must be an instance of SegmentMetadata")

    # Calculate hash of the provided data
    computed_data_hash = hypha_hash(data)

    # Debug statement for computed hash vs. expected hash
    print(f"Debug: computed_data_hash={computed_data_hash}, segment_metadata.data_hash={segment_metadata.data_hash}")

    # Verify data hash against the stored data_hash
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

        # Calculate expected hash for the entry based on previous hash and data
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
    # Combine hashes of all segments for file-level integrity
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

        # Calculate expected hash
        expected_hash = hypha_hash(f"{previous_hash}{data}".encode())
        
        if entry_hash != expected_hash:
            logger.error(f"Partial integrity check failed at entry {i}. Expected: {expected_hash}, Stored: {entry_hash}")
            return False
        logger.debug(f"Partial integrity check passed for entry {i}")

    logger.info(f"Partial lineage integrity verified up to depth {depth}")
    return True
