import os
import logging
from datetime import datetime, timezone

from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.helpers import encode_to_senary, apply_salt
from src.crypto.constants import (
    DEFAULT_HASH_FUNCTION,
    SUPPORTED_HASH_ALGORITHMS,
    SALT_SIZE,
    SEIGR_CELL_ID_PREFIX,
    SEIGR_VERSION,
)
from src.seigr_protocol.compiled.hashing_pb2 import (
    HashData,
    HashAlgorithm,
    VerificationStatus,
)
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorSeverity,
    ErrorResolutionStrategy,
)

logger = logging.getLogger(__name__)

### 📊 Hashing Functions ###


def hash_to_protobuf(
    data: bytes,
    salt: str = None,
    algorithm: str = DEFAULT_HASH_FUNCTION,
    version: int = 1,
) -> HashData:
    """
    Encodes hash data in a Protobuf format for Seigr compatibility.

    Args:
        data (bytes): The raw data to hash.
        salt (str, optional): Optional salt for hashing.
        algorithm (str): Hashing algorithm to use.
        version (int): Version identifier for the hash.

    Returns:
        HashData: A Protobuf object representing the hash data.

    Raises:
        ValueError: If an unsupported hashing algorithm is provided.
        Exception: For unexpected hashing errors.
    """
    try:
        # Validate algorithm
        algorithm_enum = (
            HashAlgorithm.Value(algorithm.upper())
            if algorithm.upper() in HashAlgorithm.keys()
            else HashAlgorithm.HASH_UNDEFINED
        )

        if algorithm_enum == HashAlgorithm.HASH_UNDEFINED:
            raise ValueError(
                f"{SEIGR_CELL_ID_PREFIX} Unsupported hash algorithm: {algorithm}"
            )

        # Generate senary-encoded hash
        senary_encoded_hash = HyphaCrypt.hypha_hash(
            data, salt=salt, algorithm=algorithm, version=version, senary_output=True
        ).split(":", 3)[3]

        # Create HashData Protobuf entry
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
            metadata={"context": "hash_generation"},
        )
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Generated HashData Protobuf: {hash_data}")
        return hash_data

    except ValueError as ve:
        logger.error(f"{SEIGR_CELL_ID_PREFIX} Hash algorithm validation failed: {ve}")
        raise
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_hash_protobuf_error",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Hash Generation",
            message="Failed to generate Protobuf hash data.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_RETRY,
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise


### 🔍 Hash Verification Functions ###


def verify_hash(data: bytes, expected_hash: str, salt: str = None) -> bool:
    """
    Verifies that the hash of the provided data matches the expected hash.

    Args:
        data (bytes): The data to verify.
        expected_hash (str): The expected hash in string format.
        salt (str, optional): Optional salt used during hashing.

    Returns:
        bool: True if the hash matches, False otherwise.

    Raises:
        ValueError: If the hash format is invalid.
    """
    try:
        # Parse the expected hash
        _, version, algorithm, expected_hash_value = expected_hash.split(":", 3)

        if algorithm not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

        # Generate actual hash
        actual_hash = HyphaCrypt.hypha_hash(
            data, salt=salt, algorithm=algorithm, senary_output=True
        )
        match = actual_hash.split(":", 3)[3] == expected_hash_value

        logger.info(
            f"{SEIGR_CELL_ID_PREFIX} Hash verification {'succeeded' if match else 'failed'}."
        )
        return match

    except ValueError as e:
        logger.error(f"{SEIGR_CELL_ID_PREFIX} Invalid hash format: {e}")
        raise
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_verification_error",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Hash Verification",
            message="Error during hash verification.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE,
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        return False


def protobuf_verify_hash(
    protobuf_hash: HashData, data: bytes, salt: str = None
) -> bool:
    """
    Verifies hash integrity using a HashData Protobuf object.

    Args:
        protobuf_hash (HashData): Protobuf hash object.
        data (bytes): Data to verify.
        salt (str, optional): Optional salt used in hashing.

    Returns:
        bool: True if hash verification succeeds, False otherwise.
    """
    try:
        formatted_hash = f"{protobuf_hash.algorithm_version}:{protobuf_hash.algorithm}:{protobuf_hash.hash_value}"
        verification_result = verify_hash(data, formatted_hash, salt=salt)

        protobuf_hash.verification_status = (
            VerificationStatus.VERIFIED
            if verification_result
            else VerificationStatus.COMPROMISED
        )

        logger.info(
            f"{SEIGR_CELL_ID_PREFIX} Protobuf hash verification status: {protobuf_hash.verification_status.name}"
        )
        return verification_result

    except Exception as e:
        logger.error(f"{SEIGR_CELL_ID_PREFIX} Protobuf hash verification failed: {e}")
        return False
