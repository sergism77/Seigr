from datetime import datetime, timezone
from typing import Optional
from src.crypto.hypha_crypt import HyphaCrypt  # ✅ Correct import
from src.crypto.constants import DEFAULT_HASH_FUNCTION, SEIGR_CELL_ID_PREFIX
from src.seigr_protocol.compiled.hashing_pb2 import HashAlgorithm, HashData
from src.logger.secure_logger import secure_logger
from src.crypto.helpers import (
    encode_to_senary,
    decode_from_senary,
    is_senary,
)
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity  # ✅ Correct Enum Import
import src.crypto.constants as constants


### 🔹 Hash Encoding Function ###
def hash_to_protobuf(
    data: bytes,
    salt: Optional[str] = None,
    algorithm: str = DEFAULT_HASH_FUNCTION,
    version: int = 1,
) -> HashAlgorithm:
    """
    **Encodes hashed data into a Protobuf format for Seigr compatibility.**
    """
    try:
        # ✅ Ensure algorithm is a string before applying `.upper()`
        if not isinstance(algorithm, str):
            raise TypeError(
                f"{SEIGR_CELL_ID_PREFIX} ❌ Algorithm must be a string, got {type(algorithm)}"
            )

        algorithm_upper = algorithm.upper()

        # ✅ Validate algorithm
        if algorithm_upper in HashAlgorithm.keys():
            algorithm_enum = HashAlgorithm.Value(algorithm_upper)
        else:
            secure_logger.log_audit_event(
                severity=constants.ALERT_SEVERITY_WARNING,  # ✅ FIXED!
                category="Hashing",
                message=f"❌ Unsupported hash algorithm detected: {algorithm_upper}",
            )
            raise ValueError(f"{SEIGR_CELL_ID_PREFIX} ❌ Unsupported hash algorithm: {algorithm}")

        # ✅ Create HyphaCrypt instance before calling `HASH_SEIGR_SENARY`
        hypha_crypt = HyphaCrypt(data=data, segment_id="seigr_hashing")
        hashed_value = hypha_crypt.HASH_SEIGR_SENARY(data, salt=salt, algorithm=algorithm)

        # ✅ Create HashData Protobuf entry
        # Ensure `algorithm_upper` is a valid enum key
        if algorithm_upper in HashAlgorithm.keys():
            algorithm_enum = HashAlgorithm.Value(algorithm_upper)
        else:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_WARNING,
                category="Hashing",
                message=f"❌ Unsupported hash algorithm detected: {algorithm_upper}",
            )
            raise ValueError(f"{SEIGR_CELL_ID_PREFIX} ❌ Unsupported hash algorithm: {algorithm}")

        # Now use it properly in Protobuf object
        hash_data = HashData(  # This should be the correct Protobuf class
            hash_id=f"{SEIGR_CELL_ID_PREFIX}_hash_{datetime.now(timezone.utc).isoformat()}",
            algorithm=algorithm_enum,  # ✅ This is now correctly set
            data_snapshot=data,
            salt=salt if salt else "",
            hash_value=hashed_value,
            algorithm_version=version,
            metadata={"context": "hash_generation"},
        )

        secure_logger.log_audit_event(
            severity=constants.ALERT_SEVERITY_INFO,  # ✅ FIXED!
            category="Hashing",
            message="✅ Successfully generated HashData Protobuf.",
            log_data=hash_data,
        )

        return hash_data

    except ValueError as ve:
        secure_logger.log_audit_event(
            severity=constants.ALERT_SEVERITY_ERROR,  # ✅ FIXED!
            category="Hashing",
            message=f"❌ Hash algorithm validation failed: {ve}",
        )
        raise

    except Exception as e:
        secure_logger.log_audit_event(
            severity=constants.ALERT_SEVERITY_CRITICAL,  # ✅ FIXED!
            category="Hashing",
            message="❌ 🚨 Failed to generate Protobuf hash data.",
        )
        raise
