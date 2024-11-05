import logging
from src.crypto.hash_utils import hypha_hash

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

def verify_segment_integrity(segment_hash: str, segment_data: dict) -> bool:
    """
    Verifies the integrity of a .seigr file segment by comparing computed hashes across multiple layers.

    Args:
        segment_hash (str): The unique identifier hash for the segment.
        segment_data (dict): Dictionary containing the segment's "data" and "hash_layers".

    Returns:
        bool: True if all integrity checks for the segment pass, False otherwise.
    """
    data = segment_data.get("data")
    hash_layers = segment_data.get("hash_layers", {})

    # Track overall validity and store layer-specific results
    all_valid = True
    layer_results = {}

    for layer_name, stored_layer_hash in hash_layers.items():
        # Compute hash at the current layer
        computed_layer_hash = hypha_hash((data + layer_name).encode())
        layer_valid = computed_layer_hash == stored_layer_hash
        layer_results[layer_name] = layer_valid

        if layer_valid:
            logger.debug(f"Integrity check passed at layer '{layer_name}' for segment '{segment_hash}'.")
        else:
            logger.error(f"Integrity check failed at layer '{layer_name}' for segment '{segment_hash}'. "
                         f"Expected: {stored_layer_hash}, Got: {computed_layer_hash}")
            all_valid = False

    if all_valid:
        logger.info(f"All integrity checks passed for segment '{segment_hash}'.")
    else:
        logger.warning(f"One or more layers failed integrity checks for segment '{segment_hash}'.")

    return all_valid

def verify_full_lineage_integrity(lineage_entries: list) -> bool:
    """
    Verifies the integrity of the entire lineage by checking each entry’s hash continuity.

    Args:
        lineage_entries (list): A list of lineage entries, where each entry is a dictionary containing 'hash',
                                'previous_hash', and 'data'.

    Returns:
        bool: True if the lineage maintains hash continuity, False otherwise.
    """
    all_valid = True

    for i, entry in enumerate(lineage_entries):
        entry_hash = entry.get("hash")
        previous_hash = entry.get("previous_hash")
        data = entry.get("data", "")

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
