import os
import logging
from datetime import datetime, timezone
from src.crypto.helpers import encode_to_senary
from src.crypto.constants import DEFAULT_HASH_FUNCTION, SUPPORTED_HASH_ALGORITHMS, SALT_SIZE, SEIGR_CELL_ID_PREFIX, SEIGR_VERSION
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import HashData, HashAlgorithm, VerificationStatus
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy
from src.crypto.hypha_crypt import HyphaCrypt

logger = logging.getLogger(__name__)

### Salt Application ###

def apply_salt(data: bytes, salt: str = None) -> bytes:
    """Applies a salt to the data if provided, generating it if not supplied."""
    try:
        salt = salt.encode() if salt else os.urandom(SALT_SIZE)
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} Applied salt to data.")
        return salt + data
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_salt_application_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Salt Application",
            message="Salt application failed.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise ValueError("Salt application error") from e

### Hashing Functions ###

def hypha_hash(data: bytes, salt: str = None, algorithm: str = "hypha_hash", version: int = 1, senary_output: bool = False) -> str:
    """
    Generates a secure hash of the provided data using HyphaCrypt with optional salting.
    """
    if algorithm not in SUPPORTED_HASH_ALGORITHMS:
        raise ValueError(f"{SEIGR_CELL_ID_PREFIX}_unsupported_algorithm: Unsupported hashing algorithm: {algorithm}")

    salted_data = apply_salt(data, salt)
    hash_result = SUPPORTED_HASH_ALGORITHMS[algorithm](salted_data)
    formatted_output = encode_to_senary(hash_result) if senary_output else hash_result.hex()
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Generated hash using {algorithm}.")
    return f"{SEIGR_VERSION}:{version}:{algorithm}:{formatted_output}"

def hash_to_protobuf(data: bytes, salt: str = None, algorithm: str = DEFAULT_HASH_FUNCTION, version: int = 1) -> HashData:
    """
    Encodes hash data in protocol buffer format with optional senary encoding for Seigr compatibility.
    """
    algorithm_enum = HashAlgorithm.Value(algorithm.upper()) if algorithm.upper() in HashAlgorithm.keys() else HashAlgorithm.HASH_UNDEFINED

    senary_encoded_hash = hypha_hash(data, salt=salt, algorithm=algorithm, version=version, senary_output=True).split(":", 3)[3]
    
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
        try:
            _, version, algorithm, expected_hash_value = expected_hash.split(":", 3)
        except ValueError as e:
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
        
        actual_hash = hypha_hash(data, salt=salt, algorithm=algorithm, senary_output=True)
        match = actual_hash.split(":", 3)[3] == expected_hash_value
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} Hash verification result: {'Match' if match else 'No Match'} for hash: {actual_hash}")
        return match
    except Exception as e:
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
    formatted_hash = f"{protobuf_hash.algorithm_version}:{protobuf_hash.algorithm}:{protobuf_hash.hash_value}"
    verification_result = verify_hash(data, formatted_hash, salt=salt)
    
    status = VerificationStatus.VERIFIED if verification_result else VerificationStatus.COMPROMISED
    protobuf_hash.verification_status = status
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Protobuf hash verification status: {status.name} for hash ID: {protobuf_hash.hash_id}")
    
    return verification_result
