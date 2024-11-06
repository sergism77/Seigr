# src/crypto/hash_utils.py

import hashlib
import logging
from src.dot_seigr.seigr_constants import DEFAULT_ALGORITHM, SUPPORTED_ALGORITHMS
from src.crypto.encoding_utils import encode_to_senary, cbor_encode_senary, cbor_decode_senary

logger = logging.getLogger(__name__)

def hypha_hash(data: bytes, salt: str = None, algorithm: str = DEFAULT_ALGORITHM, version: int = 1, senary_output: bool = False) -> str:
    """
    Generates a secure hash of the provided data with optional salting, algorithm choice, and versioning.
    
    Args:
        data (bytes): The binary data to hash.
        salt (str): Optional salt to further randomize the hash.
        algorithm (str): Hashing algorithm to use, default is SHA-256.
        version (int): Version identifier to track format or algorithm changes over time.
        senary_output (bool): Whether to output the hash in senary format for .seigr compatibility.

    Returns:
        str: A formatted string representing the hash, prefixed with version and algorithm info,
             optionally in senary encoding.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}. Supported options are: {list(SUPPORTED_ALGORITHMS.keys())}")

    # Apply optional salting
    if salt:
        data = salt.encode() + data
        logger.debug(f"Data after salting: {data}")

    # Compute the hash using the selected algorithm
    hash_function = SUPPORTED_ALGORITHMS[algorithm]
    hash_result = hash_function(data).digest()  # Obtain raw bytes for flexibility with encoding
    logger.debug(f"Generated raw hash: {hash_result} (algorithm: {algorithm}, version: {version})")

    # If senary output is requested, encode hash to senary format
    if senary_output:
        senary_hash = encode_to_senary(hash_result)
        logger.debug(f"Senary-encoded hash: {senary_hash}")
        return f"{version}:{algorithm}:{senary_hash}"
    else:
        hex_hash = hash_result.hex()
        logger.debug(f"Hexadecimal hash: {hex_hash}")
        return f"{version}:{algorithm}:{hex_hash}"

def hash_to_cbor(data: bytes, salt: str = None, algorithm: str = DEFAULT_ALGORITHM, version: int = 1) -> bytes:
    """
    Encodes hash data in CBOR format with optional senary encoding for .seigr compatibility.
    
    Args:
        data (bytes): The binary data to hash.
        salt (str): Optional salt to apply to the data.
        algorithm (str): The hashing algorithm to use.
        version (int): The version of the hashing function.
    
    Returns:
        bytes: CBOR-encoded representation of the hashed data.
    """
    hash_result = hypha_hash(data, salt=salt, algorithm=algorithm, version=version, senary_output=True)
    cbor_encoded = cbor_encode_senary({"hash": hash_result})
    logger.debug(f"CBOR-encoded hash data: {cbor_encoded}")
    return cbor_encoded

def verify_hash(data: bytes, expected_hash: str, salt: str = None, algorithm: str = DEFAULT_ALGORITHM, version: int = 1) -> bool:
    """
    Verifies that the hash of the provided data matches the expected hash.
    
    Args:
        data (bytes): The binary data to hash and verify.
        expected_hash (str): The hash to compare against, in senary or hex format with version and algorithm prefix.
        salt (str): Optional salt to apply to the data.
        algorithm (str): The hashing algorithm to use.
        version (int): The version of the hashing function.
    
    Returns:
        bool: True if the hash matches the expected hash, otherwise False.
    """
    # Remove the version and algorithm prefix from the expected hash for comparison
    _, expected_algo, expected_hash_value = expected_hash.split(":", 2)
    actual_hash = hypha_hash(data, salt=salt, algorithm=expected_algo, version=version)
    match = actual_hash.split(":", 2)[2] == expected_hash_value
    logger.debug(f"Verification result: {'Match' if match else 'No Match'} for hash: {actual_hash}")
    return match

def cbor_verify_hash(cbor_data: bytes, data: bytes, salt: str = None) -> bool:
    """
    Verifies hash integrity of CBOR-encoded data by comparing against recalculated hash.
    
    Args:
        cbor_data (bytes): CBOR-encoded data containing the hash to verify.
        data (bytes): Original data to compare against the hash in the CBOR data.
        salt (str): Optional salt for the hashing process.
    
    Returns:
        bool: True if the hash within CBOR matches the calculated hash of the data, otherwise False.
    """
    decoded_data = cbor_decode_senary(cbor_data)
    expected_hash = decoded_data.get("hash")
    match = verify_hash(data, expected_hash, salt=salt)
    logger.debug(f"CBOR verification result: {'Match' if match else 'No Match'}")
    return match
