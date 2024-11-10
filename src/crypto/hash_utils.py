# src/crypto/hash_utils.py

import hashlib
import logging
from src.dot_seigr.seigr_constants import DEFAULT_ALGORITHM, SUPPORTED_ALGORITHMS
from src.crypto.encoding_utils import encode_to_senary
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import HashData

logger = logging.getLogger(__name__)

def hypha_hash(data: bytes, salt: str = None, algorithm: str = DEFAULT_ALGORITHM, version: int = 1, senary_output: bool = False) -> bytes:
    """
    Generates a secure hash of the provided data with optional salting, algorithm choice, and versioning.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}. Supported options are: {list(SUPPORTED_ALGORITHMS.keys())}")

    if salt:
        data = salt.encode() + data
        logger.debug(f"Data after salting: {data}")

    hash_function = SUPPORTED_ALGORITHMS[algorithm]
    hash_result = hash_function(data).digest()
    logger.debug(f"Generated raw hash: {hash_result} (algorithm: {algorithm}, version: {version})")

    # Return senary-encoded string if requested; otherwise return bytes
    if senary_output:
        senary_hash = encode_to_senary(hash_result)
        logger.debug(f"Senary-encoded hash: {senary_hash}")
        return f"{version}:{algorithm}:{senary_hash}"
    else:
        return hash_result  # Return as bytes to allow for .hex() in calling code
    
def hash_to_protobuf(data: bytes, salt: str = None, algorithm: str = DEFAULT_ALGORITHM, version: int = 1) -> HashData:
    """
    Encodes hash data in protocol buffer format with optional senary encoding for .seigr compatibility.
    
    Args:
        data (bytes): The binary data to hash.
        salt (str): Optional salt to apply to the data.
        algorithm (str): The hashing algorithm to use.
        version (int): The version of the hashing function.
    
    Returns:
        HashData: Protocol buffer message containing the hashed data and metadata.
    """
    # Obtain the senary hash without prefixing version and algorithm (protobuf only needs hash value)
    hash_result = hypha_hash(data, salt=salt, algorithm=algorithm, version=version, senary_output=True).split(":", 2)[2]
    hash_data = HashData(
        version=version,
        algorithm=algorithm,
        hash_value=hash_result
    )
    logger.debug(f"Generated protocol buffer HashData: {hash_data}")
    return hash_data

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
    _, expected_algo, expected_hash_value = expected_hash.split(":", 2)
    actual_hash = hypha_hash(data, salt=salt, algorithm=expected_algo, version=version)
    match = actual_hash.split(":", 2)[2] == expected_hash_value
    logger.debug(f"Hash verification result: {'Match' if match else 'No Match'} for hash: {actual_hash}")
    return match

def protobuf_verify_hash(protobuf_hash: HashData, data: bytes, salt: str = None) -> bool:
    """
    Verifies hash integrity of data by comparing against a HashData protobuf message.
    
    Args:
        protobuf_hash (HashData): Protocol buffer containing the expected hash information.
        data (bytes): Original data to compare against the hash in the protobuf.
        salt (str): Optional salt for the hashing process.
    
    Returns:
        bool: True if the hash in the protobuf matches the calculated hash of the data, otherwise False.
    """
    # Generate hash in the same format as the protobuf's
    actual_hash = hypha_hash(data, salt=salt, algorithm=protobuf_hash.algorithm, version=protobuf_hash.version, senary_output=True)
    expected_hash = f"{protobuf_hash.version}:{protobuf_hash.algorithm}:{protobuf_hash.hash_value}"
    match = verify_hash(data, expected_hash, salt=salt)
    logger.debug(f"Protocol buffer hash verification result: {'Match' if match else 'No Match'}")
    return match
