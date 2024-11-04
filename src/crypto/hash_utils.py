# src/crypto/hash_utils.py

import hashlib
import logging
from src.dot_seigr.seigr_constants import DEFAULT_ALGORITHM, SUPPORTED_ALGORITHMS

logger = logging.getLogger(__name__)

def hypha_hash(data: bytes, salt: str = None, algorithm: str = DEFAULT_ALGORITHM, version: int = 1) -> str:
    """
    Generates a secure hash of the provided data with optional salting, algorithm choice, and versioning for future updates.
    
    Args:
        data (bytes): The binary data to hash.
        salt (str): Optional salt to further randomize the hash.
        algorithm (str): Hashing algorithm to use, default is SHA-256.
        version (int): Version identifier to track format or algorithm changes over time.

    Returns:
        str: A hexadecimal string representing the hash, prefixed with version and algorithm info.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}. Supported options are: {list(SUPPORTED_ALGORITHMS.keys())}")

    # Apply optional salting
    if salt:
        data = salt.encode() + data

    # Compute the hash using the selected algorithm
    hash_function = SUPPORTED_ALGORITHMS[algorithm]
    hash_result = hash_function(data).hexdigest()
    logger.debug(f"Generated hypha hash: {hash_result} with salt: {salt}, algorithm: {algorithm}, version: {version}")

    # Return the hash with metadata prefix for versioning and flexibility
    return f"{version}:{algorithm}:{hash_result}"
