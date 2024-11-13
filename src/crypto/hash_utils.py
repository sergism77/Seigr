import os
import hashlib
import logging
from datetime import datetime, timezone
from dot_seigr.seigr_constants import DEFAULT_ALGORITHM, SUPPORTED_ALGORITHMS
from src.crypto.encoding_utils import encode_to_senary
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import HashData, HashAlgorithm, VerificationStatus
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy

logger = logging.getLogger(__name__)

def apply_salt(data: bytes, salt: str = None, salt_length: int = 16) -> bytes:
    """Applies salt to the data if provided, generating if not supplied."""
    salt = salt.encode() if salt else os.urandom(salt_length)
    salted_data = salt + data
    logger.debug(f"Data after salting: {salted_data}")
    return salted_data

def format_hash_output(hash_result: bytes, algorithm: str, version: int, senary_output: bool = False) -> str:
    """Formats hash result with version, algorithm, and optionally encodes to senary."""
    if senary_output:
        senary_hash = encode_to_senary(hash_result)
        formatted_output = f"{version}:{algorithm}:{senary_hash}"
    else:
        formatted_output = f"{version}:{algorithm}:{hash_result.hex()}"
    logger.debug(f"Formatted hash output: {formatted_output}")
    return formatted_output

def hypha_hash(data: bytes, salt: str = None, algorithm: str = DEFAULT_ALGORITHM, version: int = 1, senary_output: bool = False) -> str:
    """
    Generates a secure hash of the provided data with optional salting, algorithm choice, and versioning.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        error_log = ErrorLogEntry(
            error_id="unsupported_algorithm",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Hashing",
            message=f"Unsupported hashing algorithm: {algorithm}.",
            details=f"Supported options are: {list(SUPPORTED_ALGORITHMS.keys())}",
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
        )
        logger.error(f"{error_log.message} {error_log.details}")
        raise ValueError(error_log.message)
    
    salted_data = apply_salt(data, salt)
    hash_function = SUPPORTED_ALGORITHMS[algorithm]
    hash_result = hash_function(salted_data).digest()
    logger.debug(f"Generated raw hash: {hash_result} (algorithm: {algorithm}, version: {version})")

    return format_hash_output(hash_result, algorithm, version, senary_output)

def hash_to_protobuf(data: bytes, salt: str = None, algorithm: str = DEFAULT_ALGORITHM, version: int = 1) -> HashData:
    """
    Encodes hash data in protocol buffer format with optional senary encoding for Seigr compatibility.
    """
    # Determine hash algorithm enum based on string name
    algorithm_enum = HashAlgorithm.Value(algorithm.upper()) if algorithm.upper() in HashAlgorithm.keys() else HashAlgorithm.HASH_UNDEFINED

    # Generate the hash with optional senary encoding
    senary_encoded_hash = hypha_hash(data, salt=salt, algorithm=algorithm, version=version, senary_output=True).split(":", 2)[2]
    
    # Build and populate the HashData protobuf
    hash_data = HashData(
        hash_id="hash_" + datetime.now(timezone.utc).isoformat(),
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
    logger.debug(f"Generated protocol buffer HashData: {hash_data}")
    return hash_data

def verify_hash(data: bytes, expected_hash: str, salt: str = None) -> bool:
    """
    Verifies that the hash of the provided data matches the expected hash.
    """
    try:
        try:
            _, algorithm, expected_hash_value = expected_hash.split(":", 2)
        except ValueError as e:
            error_log = ErrorLogEntry(
                error_id="hash_format_error",
                severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
                component="Hash Verification",
                message="Expected hash is incorrectly formatted.",
                details=str(e),
                resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_RETRY
            )
            logger.error(f"{error_log.message}: {error_log.details}")
            raise ValueError(error_log.message)
        
        actual_hash = hypha_hash(data, salt=salt, algorithm=algorithm, senary_output=True)
        match = actual_hash.split(":", 2)[2] == expected_hash_value
        logger.debug(f"Hash verification result: {'Match' if match else 'No Match'} for hash: {actual_hash}")
        return match
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id="verification_error",
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
    
    # Update and log verification status in the protobuf
    status = VerificationStatus.VERIFIED if verification_result else VerificationStatus.COMPROMISED
    protobuf_hash.verification_status = status
    logger.debug(f"Protobuf hash verification status: {status.name} for hash ID: {protobuf_hash.hash_id}")
    
    return verification_result
