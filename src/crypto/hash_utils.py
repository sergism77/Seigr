"""
📌 **Seigr Hash Utilities**
Handles secure hashing, Protobuf encoding, and verification.
"""

from typing import Optional
from datetime import datetime, timezone

# 🔐 Seigr Imports
from src.crypto.constants import (
    DEFAULT_HASH_FUNCTION,
    SEIGR_CELL_ID_PREFIX,
    SUPPORTED_HASH_ALGORITHMS,
)
from src.crypto.hypha_crypt import HyphaCrypt
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from src.seigr_protocol.compiled.hashing_pb2 import HashAlgorithm, HashData, VerificationStatus
from src.logger.secure_logger import secure_logger  # ✅ Only using Seigr's secure logger

# ===============================
# 💡 **HyphaCrypt Hash Wrapper**
# ===============================


def seigr_HASH_SEIGR_SENARY(
    data: bytes, salt: Optional[str] = None, algorithm: str = DEFAULT_HASH_FUNCTION
) -> str:
    """
    **🔐 Use HyphaCrypt directly for hashing.**

    Args:
        data (bytes): **Input data to hash.**
        salt (Optional[str]): **Optional salt value.**
        algorithm (str): **Hash algorithm (default: DEFAULT_HASH_FUNCTION).**

    Returns:
        str: **Hashed value in senary encoding.**

    Raises:
        ValueError: **If an unsupported algorithm is used.**
    """
    if not isinstance(algorithm, str):
        raise TypeError(f"❌ Hash algorithm must be a string, got {type(algorithm)}")

    algorithm_lower = algorithm.lower()

    if algorithm_lower not in SUPPORTED_HASH_ALGORITHMS:
        raise ValueError(f"{SEIGR_CELL_ID_PREFIX} ❌ Unsupported hash algorithm: {algorithm_lower}")

    hypha_crypt = HyphaCrypt(data=data, segment_id="seigr_hashing")  # ✅ Proper instantiation
    return hypha_crypt.HASH_SEIGR_SENARY(
        salt=salt, algorithm=algorithm_lower
    )  # 🔥 Use HyphaCrypt's hash


# ===============================
# 📦 **Hashing to Protobuf**
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
        if not isinstance(algorithm, str):
            raise TypeError(
                f"{SEIGR_CELL_ID_PREFIX} ❌ Algorithm must be a string, got {type(algorithm)}"
            )

        algorithm_lower = algorithm.lower()
        algorithm_upper = algorithm.upper()

        # 🔍 Ensure algorithm is supported
        if algorithm_lower not in SUPPORTED_HASH_ALGORITHMS:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_WARNING,  # ✅ Match expected test severity
                category="Hashing",
                message=f"❌ Hash algorithm validation failed: {SEIGR_CELL_ID_PREFIX} ❌ Unsupported hash algorithm: {algorithm_lower}",
                sensitive=False,
            )
            raise ValueError(
                f"{SEIGR_CELL_ID_PREFIX} ❌ Unsupported hash algorithm: {algorithm_lower}"
            )

        # ✅ Convert algorithm to HashAlgorithm Enum safely
        try:
            if algorithm_upper in ["HASH_SEIGR_SENARY", "HYPHA_SENARY"]:
                algorithm_enum = (
                    HashAlgorithm.HASH_SEIGR_SENARY
                )  # ✅ Use Seigr's Senary hashing enum

            else:
                algorithm_enum = getattr(HashAlgorithm, f"HASH_{algorithm_upper}", None)
                if algorithm_enum is None:
                    raise ValueError(
                        f"{SEIGR_CELL_ID_PREFIX} ❌ Unsupported hash algorithm: {algorithm_lower}"
                    )
        except Exception as e:
            raise ValueError(
                f"{SEIGR_CELL_ID_PREFIX} ❌ Invalid HashAlgorithm mapping: {algorithm_upper}"
            )

        # ✅ Generate hash using HyphaCrypt
        hypha_crypt = HyphaCrypt(data, segment_id="seigr_hashing")
        hashed_value = hypha_crypt.HASH_SEIGR_SENARY(data=data, salt=salt, algorithm=algorithm_lower)  # ✅ Fix: Pass `data`

        # ✅ Construct HashData Protobuf Object
        hash_data = HashData(
            hash_id=f"{SEIGR_CELL_ID_PREFIX}_hash_{datetime.now(timezone.utc).isoformat()}",
            algorithm=algorithm_enum,
            data_snapshot=data,
            salt=salt or "",
            hash_value=hashed_value,
            algorithm_version=version,
            senary_encoded=True,
            creation_timestamp=datetime.now(timezone.utc).isoformat() + "Z",
            verification_status=VerificationStatus.VERIFICATION_PENDING,
            metadata={"context": "hash_generation"},
        )

        # ✅ Secure logging
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,  # ✅ Match expected severity
            category="Hashing",
            message="✅ Successfully generated HashData Protobuf.",
            log_data={"hash_id": hash_data.hash_id, "algorithm": algorithm_enum},
        )
        return hash_data

    except TypeError as te:
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_ERROR,
            category="Hashing",
            message="❌ Hash function received invalid type.",
            log_data={"error": str(te)},
            sensitive=False,
        )
        raise

    except ValueError as ve:
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_WARNING,  # ✅ Match test expectation
            category="Hashing",
            message=f"❌ Hash algorithm validation failed: {str(ve)}",
            log_data={"error": str(ve)},
            sensitive=False,
        )
        raise

    except Exception as e:
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,  # ✅ Match expected critical level
            category="Hashing",
            message="🚨 Failed to generate Protobuf hash data.",
            log_data={"error": str(e)},
            sensitive=False,
        )
        raise
