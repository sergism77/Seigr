import logging
from src.crypto.hash_utils import hypha_hash
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SegmentMetadata, LineageEntry, FileMetadata

logger = logging.getLogger(__name__)

def verify_integrity(stored_hash: str, senary_data: str) -> bool:
    """
    Verifies the integrity of the entire .seigr file by comparing the stored hash with a newly computed hash.

    Args:
        stored_hash (str): Expected hash value stored for the .seigr file.
        senary_data (str): Senary-encoded data used to compute the hash for verification.

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

def verify_segment_integrity(segment_metadata: SegmentMetadata) -> bool:
    """
    Verifies the integrity of a .seigr file segment by comparing computed hashes across multiple layers.

    Args:
        segment_metadata (SegmentMetadata): A protobuf SegmentMetadata message containing segment details.

    Returns:
        bool: True if all integrity checks for the segment pass, False otherwise.
    """
    data = segment_metadata.data
    hash_layers = segment_metadata.hash_layers

    # Track overall validity and store layer-specific results
    all_valid = True
    layer_results = {}

    for layer_name, stored_layer_hash in hash_layers.items():
        # Compute hash at the current layer
        computed_layer_hash = hypha_hash((data + layer_name).encode())
        layer_valid = computed_layer_hash == stored_layer_hash
        layer_results[layer_name] = layer_valid

        if layer_valid:
            logger.debug(f"Integrity check passed at layer '{layer_name}' for segment '{segment_metadata.segment_hash}'.")
        else:
            logger.error(f"Integrity check failed at layer '{layer_name}' for segment '{segment_metadata.segment_hash}'. "
                         f"Expected: {stored_layer_hash}, Got: {computed_layer_hash}")
            all_valid = False

    if all_valid:
        logger.info(f"All integrity checks passed for segment '{segment_metadata.segment_hash}'.")
    else:
        logger.warning(f"One or more layers failed integrity checks for segment '{segment_metadata.segment_hash}'.")

    return all_valid

def verify_full_lineage_integrity(lineage_proto: list[LineageEntry]) -> bool:
    """
    Verifies the integrity of the entire lineage by checking each entry’s hash continuity.

    Args:
        lineage_proto (list[LineageEntry]): A list of protobuf LineageEntry messages.

    Returns:
        bool: True if the lineage maintains hash continuity, False otherwise.
    """
    all_valid = True

    for i, entry in enumerate(lineage_proto):
        entry_hash = entry.hash
        previous_hash = entry.previous_hash
        data = entry.data

        # Compute expected hash for the current entry
        expected_hash = hypha_hash((data + previous_hash).encode()) if previous_hash else hypha_hash(data.encode())
        
        if entry_hash != expected_hash:
            logger.error(f"Integrity check failed for lineage entry {i}. Expected hash: {expected_hash}, "
                         f"Stored hash: {entry_hash}")
            all_valid = False
        else:
            logger.debug(f"Integrity check passed for lineage entry {i}. Hash: {entry_hash}")

    if all_valid:
        logger.info("Full lineage integrity check passed.")
    else:
        logger.warning("Full lineage integrity check failed. Discrepancies found in one or more entries.")

    return all_valid

def verify_file_metadata_integrity(file_metadata: FileMetadata) -> bool:
    """
    Verifies the integrity of the entire file metadata by computing and comparing the stored and computed file hash.

    Args:
        file_metadata (FileMetadata): A protobuf FileMetadata message.

    Returns:
        bool: True if the file's hash is accurate and matches the computed hash.
    """
    # Combine segment hashes to verify the overall file hash
    combined_segment_hashes = "".join([segment.segment_hash for segment in file_metadata.segments])
    computed_file_hash = hypha_hash(combined_segment_hashes.encode())

    if file_metadata.file_hash == computed_file_hash:
        logger.info("File metadata integrity check passed.")
        return True
    else:
        logger.warning(f"File metadata integrity check failed. Expected: {file_metadata.file_hash}, "
                       f"Got: {computed_file_hash}")
        return False
