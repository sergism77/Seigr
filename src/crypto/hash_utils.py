import os
import logging
from datetime import datetime, timezone
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.helpers import encode_to_senary, apply_salt
from src.crypto.constants import DEFAULT_HASH_FUNCTION, SUPPORTED_HASH_ALGORITHMS, SALT_SIZE, SEIGR_CELL_ID_PREFIX, SEIGR_VERSION
from src.seigr_protocol.compiled.hashing_pb2 import HashData, HashAlgorithm, VerificationStatus
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy

logger = logging.getLogger(__name__)

### Hashing Functions ###

def hash_to_protobuf(data: bytes, salt: str = None, algorithm: str = DEFAULT_HASH_FUNCTION, version: int = 1) -> HashData:
    """
    Encodes hash data in protocol buffer format with optional senary encoding for Seigr compatibility.
    """
    # Select algorithm enum or set as undefined if algorithm not found in HashAlgorithm enum
    algorithm_enum = HashAlgorithm.Value(algorithm.upper()) if algorithm.upper() in HashAlgorithm.keys() else HashAlgorithm.HASH_UNDEFINED

    # Generate senary-encoded hash using HyphaCrypt.hypha_hash
    senary_encoded_hash = HyphaCrypt.hypha_hash(data, salt=salt, algorithm=algorithm, version=version, senary_output=True).split(":", 3)[3]
    
    # Construct the HashData protobuf object
    hash_data = HashData(
        hash_id=f"{SEIGR_CELL_ID_PREFIX}_hash_{datetime.now(timezone.utc).isoformat()}",
        algorithm=algorithm_enum,
        data_snapshot=data,
        salt=salt if salt else "",
        hash_value=senary_encoded_hash,
        algorithm_version=version,
        senary_encoded=True,
        creation_timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        verification_status=VerificationStatus.PENDING,
        metadata={"context": "hash_generation"}
    )
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Generated protocol buffer HashData: {hash_data}")
    return hash_data

### Hash Verification Functions ###

def verify_hash(data: bytes, expected_hash: str, salt: str = None) -> bool:
    """
    Verifies that the hash of the provided data matches the expected hash.
    """
    try:
        # Split expected hash format into version, algorithm, and hash components
        _, version, algorithm, expected_hash_value = expected_hash.split(":", 3)
        
        # Compute the hash and verify by comparing with expected hash
        actual_hash = HyphaCrypt.hypha_hash(data, salt=salt, algorithm=algorithm, senary_output=True)
        match = actual_hash.split(":", 3)[3] == expected_hash_value
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} Hash verification result: {'Match' if match else 'No Match'} for hash: {actual_hash}")
        return match
    except ValueError as e:
        # Log and raise error if expected hash format is incorrect
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_hash_format_error",
            severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
            component="Hash Verification",
            message="Expected hash is incorrectly formatted.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_RETRY
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise ValueError(error_log.message)
    except Exception as e:
        # Log error and return False if hash verification encounters an error
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_verification_error",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Hash Verification",
            message="Hash verification encountered an error.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        return False

def protobuf_verify_hash(protobuf_hash: HashData, data: bytes, salt: str = None) -> bool:
    """
    Verifies hash integrity of data by comparing against a HashData protobuf message.
    """
    # Format hash string from protobuf hash object for comparison
    formatted_hash = f"{protobuf_hash.algorithm_version}:{protobuf_hash.algorithm}:{protobuf_hash.hash_value}"
    
    # Perform hash verification and update the protobuf verification status
    verification_result = verify_hash(data, formatted_hash, salt=salt)
    status = VerificationStatus.VERIFIED if verification_result else VerificationStatus.COMPROMISED
    protobuf_hash.verification_status = status
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Protobuf hash verification status: {status.name} for hash ID: {protobuf_hash.hash_id}")
    
    return verification_result
