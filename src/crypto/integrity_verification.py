# src/crypto/integrity_verification.py

import logging
from datetime import datetime, timezone
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.hash_utils import hypha_hash, verify_hash
from src.crypto.encoding_utils import encode_to_senary, decode_from_senary, is_senary
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import IntegrityVerification

logger = logging.getLogger(__name__)

def generate_integrity_hash(data: bytes, salt: str = None, use_senary: bool = True) -> str:
    """
    Generates a primary integrity hash for the given data, optionally encoded in senary.

    Args:
        data (bytes): The data to hash.
        salt (str, optional): An optional salt to add randomness to the hash.
        use_senary (bool): Whether to encode the output in senary.

    Returns:
        str: The generated hash, senary-encoded if use_senary is True.
    """
    integrity_hash = hypha_hash(data, salt=salt, senary_output=use_senary)
    logger.info(f"Generated integrity hash: {integrity_hash} (senary: {use_senary})")
    return integrity_hash

def verify_integrity(data: bytes, expected_hash: str, salt: str = None) -> bool:
    """
    Verifies the integrity of the given data against an expected hash.

    Args:
        data (bytes): The original data to hash and compare.
        expected_hash (str): The expected hash, either senary or hex encoded.
        salt (str, optional): Salt used when hashing.

    Returns:
        bool: True if the generated hash matches the expected hash, False otherwise.
    """
    use_senary = is_senary(expected_hash)
    match = verify_hash(data, expected_hash, salt=salt, senary_output=use_senary)
    logger.info(f"Integrity verification result: {'Match' if match else 'No Match'} for hash: {expected_hash}")
    return match

def log_integrity_verification(status: str, verifier_id: str, integrity_level: str = "FULL", details: dict = None) -> IntegrityVerification:
    """
    Logs the result of an integrity verification process as a protocol buffer message.

    Args:
        status (str): The verification status (e.g., "SUCCESS", "FAILED").
        verifier_id (str): ID of the verifier or system component performing the check.
        integrity_level (str, optional): Level of integrity verification (e.g., "FULL", "QUICK").
        details (dict, optional): Additional details about the verification.

    Returns:
        IntegrityVerification: The generated protocol buffer log entry for the verification event.
    """
    verification_entry = IntegrityVerification(
        status=status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        verifier_id=verifier_id,
        integrity_level=integrity_level,
        details=details if details else {}
    )
    logger.info(f"Logged integrity verification: {verification_entry}")
    return verification_entry

def create_hierarchical_hashes(data: bytes, layers: int = 3, salt: str = None, use_senary: bool = True) -> dict:
    """
    Creates a hierarchy of hashes to provide additional integrity verification layers.

    Args:
        data (bytes): The original data to hash.
        layers (int, optional): The number of hierarchical layers.
        salt (str, optional): Salt for additional security.
        use_senary (bool): Whether to encode each hash layer in senary.

    Returns:
        dict: A dictionary representing each layer of hashed data, senary-encoded if use_senary is True.
    """
    crypt_instance = HyphaCrypt(data, segment_id="segment", use_senary=use_senary)
    hierarchy = crypt_instance.compute_layered_hashes(layers)
    logger.info(f"Generated hierarchical hashes with {layers} layers.")
    return hierarchy

def verify_hierarchical_integrity(data: bytes, reference_hierarchy: dict, layers: int = 3, salt: str = None) -> bool:
    """
    Verifies integrity using a hierarchical hash structure.

    Args:
        data (bytes): The original data.
        reference_hierarchy (dict): The reference hierarchy to compare against.
        layers (int, optional): The depth of verification layers.
        salt (str, optional): Salt for consistency in hashing.

    Returns:
        bool: True if the generated hash hierarchy matches the reference up to the specified layers, otherwise False.
    """
    generated_hierarchy = create_hierarchical_hashes(data, layers=layers, salt=salt)
    
    for layer in range(1, layers + 1):
        generated_hash = generated_hierarchy.get(f"Layer_{layer}")
        reference_hash = reference_hierarchy.get(f"Layer_{layer}")
        
        if generated_hash != reference_hash:
            logger.warning(f"Integrity verification failed at Layer {layer}")
            return False
    
    logger.info("Hierarchical integrity verified successfully.")
    return True

def encode_and_log_integrity(data: bytes, verifier_id: str, salt: str = None, use_senary: bool = True, integrity_level: str = "FULL") -> IntegrityVerification:
    """
    Generates a senary-encoded integrity hash, logs the verification, and returns the log entry.

    Args:
        data (bytes): Data for hash generation.
        verifier_id (str): ID of the verifier.
        salt (str, optional): Salt to apply to the data.
        use_senary (bool): Whether to encode the hash in senary format.
        integrity_level (str): Level of integrity verification.

    Returns:
        IntegrityVerification: The protocol buffer log entry.
    """
    integrity_hash = generate_integrity_hash(data, salt=salt, use_senary=use_senary)
    verification_status = "SUCCESS" if integrity_hash else "FAILED"
    return log_integrity_verification(
        status=verification_status,
        verifier_id=verifier_id,
        integrity_level=integrity_level,
        details={"integrity_hash": integrity_hash}
    )
