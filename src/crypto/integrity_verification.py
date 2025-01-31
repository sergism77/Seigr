"""
📌 **Integrity Verification Module**
Handles **multi-layer integrity verification**, **hierarchical hashing**, and **monitoring cycles** 
in accordance with **Seigr security protocols**.
"""

import logging
from datetime import datetime, timedelta, timezone

# 🔐 Seigr Imports
from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.encoding_utils import is_senary
from src.crypto.hash_utils import hypha_hash, verify_hash
from src.crypto.hypha_crypt import HyphaCrypt
from src.logger.secure_logger import secure_logger
from src.crypto.alert_utils import trigger_alert  # ✅ Use centralized alerting
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity, AlertType
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity
from src.seigr_protocol.compiled.integrity_pb2 import IntegrityVerification, MonitoringCycleResult

logger = logging.getLogger(__name__)

# ===============================
# 🔑 **Primary Integrity Hashing**
# ===============================

def generate_integrity_hash(data: bytes, salt: str = None, use_senary: bool = True) -> str:
    """
    Generates a **secure integrity hash** for the given data.

    Args:
        data (bytes): **Data to be hashed.**
        salt (str, optional): **Salt for added security.**
        use_senary (bool): **Whether to encode the hash in senary.**

    Returns:
        str: **Generated integrity hash.**
    """
    try:
        integrity_hash = hypha_hash(data, salt=salt, senary_output=use_senary)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Integrity",
            message=f"{SEIGR_CELL_ID_PREFIX} Generated integrity hash successfully.",
        )
        return integrity_hash
    except Exception as e:
        _log_error("integrity_hash_fail", "Integrity hash generation failed", e)
        raise ValueError("Integrity hash generation failed.") from e

# ===============================
# ✅ **Integrity Verification**
# ===============================

def verify_integrity(data: bytes, expected_hash: str, salt: str = None) -> bool:
    """
    **Verifies the integrity** of the given data against an expected hash.

    Args:
        data (bytes): **Data to verify.**
        expected_hash (str): **Expected hash for verification.**
        salt (str, optional): **Salt used during hashing.**

    Returns:
        bool: **True if verification succeeds, False otherwise.**
    """
    try:
        use_senary = is_senary(expected_hash)
        match = verify_hash(data, expected_hash, salt=salt, senary_output=use_senary)

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Integrity",
            message=f"{SEIGR_CELL_ID_PREFIX} Integrity verification {'successful' if match else 'failed'}.",
        )

        return match
    except Exception as e:
        _log_error("integrity_verification_fail", "Integrity verification failed", e)
        raise ValueError("Integrity verification failed.") from e

# ===============================
# 📊 **Logging Integrity Verification**
# ===============================

def log_integrity_verification(
    status: str, verifier_id: str, integrity_level: str = "FULL", details: dict = None
) -> IntegrityVerification:
    """
    Logs the result of an **integrity verification process** as a structured **protocol buffer message**.

    Args:
        status (str): **Verification status.**
        verifier_id (str): **Identifier of the verifier.**
        integrity_level (str): **Level of integrity verification.**
        details (dict, optional): **Additional details.**

    Returns:
        IntegrityVerification: **Protobuf log entry.**
    """
    verification_entry = IntegrityVerification(
        status=status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        verifier_id=verifier_id,
        integrity_level=integrity_level,
        details=details or {},
    )

    secure_logger.log_audit_event(
        severity=AlertSeverity.ALERT_SEVERITY_INFO,
        category="Integrity",
        message=f"{SEIGR_CELL_ID_PREFIX} Logged integrity verification: {verification_entry.status}",
    )

    return verification_entry

# ===============================
# 🏗️ **Hierarchical Hashing**
# ===============================

def create_hierarchical_hashes(
    data: bytes, layers: int = 3, salt: str = None, use_senary: bool = True
) -> dict:
    """
    Creates a **multi-layered hash tree** to strengthen integrity verification.

    Args:
        data (bytes): **Data to hash.**
        layers (int): **Number of hierarchical layers.**
        salt (str, optional): **Salt for added security.**
        use_senary (bool): **Whether to encode in senary format.**

    Returns:
        dict: **Structured hierarchy of hash layers.**
    """
    try:
        crypt_instance = HyphaCrypt(
            data,
            segment_id=f"{SEIGR_CELL_ID_PREFIX}_segment",
            hash_depth=layers,
            use_senary=use_senary,
        )
        hierarchy = crypt_instance.compute_layered_hashes()

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Integrity",
            message=f"{SEIGR_CELL_ID_PREFIX} Created hierarchical hash layers: {layers} layers.",
        )

        return hierarchy
    except Exception as e:
        _log_error("hierarchical_hash_fail", "Hierarchical hash generation failed", e)
        raise ValueError("Hierarchical hashing failed.") from e

# ===============================
# 📅 **Monitoring Cycle Management**
# ===============================

def generate_monitoring_cycle(
    cycle_id: str,
    segments_status: list,
    total_threats_detected: int,
    new_threats_detected: int,
    interval_senary: str = "10",
) -> MonitoringCycleResult:
    """
    Generates a **structured monitoring cycle** for security threat detection.

    Returns:
        MonitoringCycleResult: **Monitoring cycle protocol buffer message.**
    """
    try:
        next_cycle_date = datetime.now(timezone.utc) + timedelta(days=int(interval_senary, 6))

        monitoring_cycle = MonitoringCycleResult(
            cycle_id=cycle_id,
            segments_status=segments_status,
            completed_at=datetime.now(timezone.utc).isoformat(),
            total_threats_detected=total_threats_detected,
            new_threats_detected=new_threats_detected,
            next_cycle_scheduled=next_cycle_date.isoformat(),
        )

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Monitoring",
            message=f"{SEIGR_CELL_ID_PREFIX} Monitoring cycle logged successfully.",
        )

        return monitoring_cycle
    except Exception as e:
        _log_error("monitoring_cycle_fail", "Monitoring cycle generation failed", e)
        raise ValueError("Monitoring cycle failed.") from e

# ===============================
# ⚠️ **Internal Error Logging**
# ===============================

def _log_error(error_id, message, exception):
    """
    Logs **critical errors** in integrity verification.

    Args:
        error_id (str): **Unique error identifier.**
        message (str): **Error message.**
        exception (Exception): **Raised exception.**
    """
    error_log = ErrorLogEntry(
        error_id=f"{SEIGR_CELL_ID_PREFIX}_{error_id}",
        severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
        component="Integrity Verification",
        message=message,
        details=str(exception),
    )

    secure_logger.log_audit_event(
        severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
        category="Integrity Verification",
        message=f"{SEIGR_CELL_ID_PREFIX} {message}: {exception}",
    )

    logger.error(f"{SEIGR_CELL_ID_PREFIX} {message}: {exception}")
