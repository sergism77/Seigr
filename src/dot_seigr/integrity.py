import logging
from ..crypto.hypha_crypt import hypha_hash

logger = logging.getLogger(__name__)

def verify_integrity(stored_hash: str, senary_data: str) -> bool:
    """
    Verifies integrity by comparing the computed hash with the stored hash.

    Args:
        stored_hash (str): Expected hash value stored for the segment.
        senary_data (str): Senary-encoded data to compute the hash for verification.

    Returns:
        bool: True if integrity check passes, False otherwise.
    """
    computed_hash = hypha_hash(senary_data.encode())
    valid = computed_hash == stored_hash
    
    if valid:
        logger.info(f"Integrity check passed for .seigr file. Computed hash matches stored hash: {stored_hash}")
    else:
        logger.warning(f"Integrity check failed for .seigr file. Stored hash: {stored_hash}, Computed hash: {computed_hash}")

    return valid

def verify_segment_integrity(segment_hash: str, segment_data: dict) -> bool:
    """
    Verifies the integrity of a .seigr file segment with multi-dimensional checks.

    Args:
        segment_hash (str): Hash to verify.
        segment_data (dict): Segment data for verification.

    Returns:
        bool: True if segment passes integrity checks, False if any fail.
    """
    all_valid = True

    for hash_layer, stored_hash in segment_data["hash_layers"].items():
        computed_hash = hypha_hash(segment_data["data"].encode())
        if computed_hash != stored_hash:
            logger.error(f"Integrity check failed at layer {hash_layer} for segment {segment_hash}")
            all_valid = False
        else:
            logger.debug(f"Integrity check passed at layer {hash_layer} for segment {segment_hash}")

    if all_valid:
        logger.info(f"All hash layers passed for segment {segment_hash}.")
    else:
        logger.warning(f"One or more layers failed integrity checks for segment {segment_hash}.")

    return all_valid
