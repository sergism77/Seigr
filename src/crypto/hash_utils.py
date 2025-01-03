import logging
from datetime import datetime, timezone

from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.constants import (
    DEFAULT_HASH_FUNCTION,
    SUPPORTED_HASH_ALGORITHMS,
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
    Generates a hash of the provided data and encodes it in a HashData Protobuf object.

    Args:
        data (bytes): Data to hash.
        salt (str, optional): Optional salt for hashing.
        algorithm (str): Hashing algorithm (default is set in constants).
        version (int): Algorithm version identifier.

    Returns:
        HashData: Protobuf object containing hash information.

    Raises:
        ValueError: If the specified algorithm is unsupported.
    """
    try:
        if algorithm.upper() not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(
                f"{SEIGR_CELL_ID_PREFIX} Unsupported hash algorithm: {algorithm}"
            )

        # Map algorithm to Protobuf enum
        algorithm_enum = (
            HashAlgorithm.Value(algorithm.upper())
            if algorithm.upper() in HashAlgorithm.keys()
            else HashAlgorithm.HASH_UNDEFINED
        )

        if algorithm_enum == HashAlgorithm.HASH_UNDEFINED:
            raise ValueError(
                f"{SEIGR_CELL_ID_PREFIX} Algorithm enum mapping failed for: {algorithm}"
            )

        # Generate senary-encoded hash
        senary_encoded_hash = HyphaCrypt.hypha_hash(
            data, salt=salt, algorithm=algorithm, version=version, senary_output=True
        ).split(":", 3)[3]

        # Construct HashData Protobuf object
        hash_data = HashData(
            hash_id=f"{SEIGR_CELL_ID_PREFIX}_hash_{datetime.now(timezone.utc).isoformat()}",
            algorithm=algorithm_enum,
            data_snapshot=data,
            salt=salt or "",
            hash_value=senary_encoded_hash,
            algorithm_version=version,
            senary_encoded=True,
            creation_timestamp=datetime.now(timezone.utc).isoformat() + "Z",
            verification_status=VerificationStatus.PENDING,
            metadata={"context": "hash_generation"},
        )

        logger.info(
            f"{SEIGR_CELL_ID_PREFIX} Successfully generated HashData Protobuf: {hash_data}"
        )
        return hash_data

    except ValueError as ve:
        logger.error(f"{SEIGR_CELL_ID_PREFIX} Hash generation failed: {ve}")
        raise
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_hash_generation_error",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Hash Generation",
            message="Unexpected error during hash generation.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE,
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise


### 🔍 Hash Verification Functions ###

def verify_hash(data: bytes, expected_hash: str, salt: str = None) -> bool:
    """
    Verifies that the hash of the provided data matches the expected hash.

    Args:
        data (bytes): Data to verify.
        expected_hash (str): Expected hash in formatted string.
        salt (str, optional): Optional salt used in hashing.

    Returns:
        bool: True if the hash matches, False otherwise.

    Raises:
        ValueError: If the hash format is invalid.
    """
    try:
        _, version, algorithm, expected_hash_value = expected_hash.split(":", 3)

        if algorithm not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f"{SEIGR_CELL_ID_PREFIX} Unsupported algorithm: {algorithm}")

        # Compute hash and compare
        actual_hash = HyphaCrypt.hypha_hash(
            data, salt=salt, algorithm=algorithm, senary_output=True
        ).split(":", 3)[3]

        match = actual_hash == expected_hash_value

        logger.info(
            f"{SEIGR_CELL_ID_PREFIX} Hash verification result: {'Match' if match else 'Mismatch'}"
        )
        return match

    except ValueError as ve:
        logger.error(f"{SEIGR_CELL_ID_PREFIX} Invalid hash format: {ve}")
        raise
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_hash_verification_error",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Hash Verification",
            message="Unexpected error during hash verification.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE,
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        return False


def protobuf_verify_hash(protobuf_hash: HashData, data: bytes, salt: str = None) -> bool:
    """
    Verifies the integrity of data using a HashData Protobuf object.

    Args:
        protobuf_hash (HashData): HashData Protobuf object.
        data (bytes): Data to verify.
        salt (str, optional): Optional salt for hashing.

    Returns:
        bool: True if verification succeeds, False otherwise.
    """
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
