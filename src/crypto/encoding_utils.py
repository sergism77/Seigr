"""
📌 **Seigr Encoding Utilities**
Handles **hash encoding, verification, and Protobuf-based integrity validation**.
Ensures full **Seigr compliance**, secure cryptographic operations, and **structured error logging**.
"""

from datetime import datetime, timezone
from typing import Optional

# 🔐 Seigr Imports
from src.crypto.constants import (
    DEFAULT_HASH_FUNCTION,
    SEIGR_CELL_ID_PREFIX,
    SUPPORTED_HASH_ALGORITHMS,
)
from src.crypto.helpers import encode_to_senary, decode_from_senary, is_senary
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
    ErrorSeverity,
)
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from src.seigr_protocol.compiled.hashing_pb2 import HashAlgorithm, HashData, VerificationStatus

# ===============================
# 📊 **Hashing Functions**
# ===============================


def hash_to_protobuf(
    data: bytes,
    salt: Optional[str] = None,
    algorithm: str = DEFAULT_HASH_FUNCTION,
    version: int = 1,
) -> HashData:
    """
    **Encodes hashed data into a Protobuf format for Seigr compatibility.**
    """
    try:
        # Validate algorithm
        algorithm_enum = (
            HashAlgorithm.Value(algorithm.upper())
            if algorithm.upper() in HashAlgorithm.keys()
            else HashAlgorithm.HASH_UNDEFINED
        )

        if algorithm_enum == HashAlgorithm.HASH_UNDEFINED:
            raise ValueError(f"{SEIGR_CELL_ID_PREFIX} ❌ Unsupported hash algorithm: {algorithm}")

        # **Avoid circular import by importing inside the function**
        from src.crypto.hash_utils import hypha_hash

        # Generate **Senary-encoded hash**
        senary_encoded_hash = hypha_hash(
            data, salt=salt, algorithm=algorithm, version=version, senary_output=True
        ).split(":", 3)[3]

        # **Create HashData Protobuf entry**
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

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Hashing",
            message=f"✅ Successfully generated HashData Protobuf.",
            log_data=hash_data,
        )
        return hash_data

    except ValueError as ve:
        secure_logger.log_audit_event(
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            category="Hashing",
            message=f"❌ Hash algorithm validation failed: {ve}",
        )
        raise

    except Exception as e:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_hash_protobuf_error",
            severity=ErrorSeverity.ERROR_SEVERITY_CRITICAL,
            component="Hash Generation",
            message="🚨 Failed to generate Protobuf hash data.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_RETRY,
        )
        secure_logger.log_audit_event(
            severity=ErrorSeverity.ERROR_SEVERITY_CRITICAL,
            category="Hashing",
            message=f"❌ {error_log.message}",
            log_data=error_log,
        )
        raise


# ===============================
# 🔍 **Hash Verification Functions**
# ===============================


def verify_hash(data: bytes, expected_hash: str, salt: Optional[str] = None) -> bool:
    """
    **Verifies that the computed hash matches the expected hash.**
    """
    try:
        # **Parse expected hash format**
        _, version, algorithm, expected_hash_value = expected_hash.split(":", 3)

        if algorithm not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f"{SEIGR_CELL_ID_PREFIX} ❌ Unsupported algorithm: {algorithm}")

        # Import `hypha_hash` inside the function to avoid circular import
        from src.crypto.hash_utils import hypha_hash

        # **Compute actual hash**
        actual_hash = hypha_hash(data, salt=salt, algorithm=algorithm, senary_output=True)
        match = actual_hash.split(":", 3)[3] == expected_hash_value

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Hash Verification",
            message=f"✅ Hash verification {'succeeded' if match else 'failed'}.",
        )
        return match

    except ValueError as e:
        secure_logger.log_audit_event(
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            category="Hash Verification",
            message=f"❌ Invalid hash format: {e}",
        )
        raise

    except Exception as e:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_verification_error",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Hash Verification",
            message="🚨 Error during hash verification.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE,
        )
        secure_logger.log_audit_event(
            severity=ErrorSeverity.ERROR_SEVERITY_CRITICAL,
            category="Hash Verification",
            message=f"❌ {error_log.message}",
            log_data=error_log,
        )
        return False
