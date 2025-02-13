"""
📌 **Integrity Verification Module**
Handles **multi-layer integrity verification**, **hierarchical hashing**, and **monitoring cycles** 
in accordance with **Seigr security protocols**.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

# 🔐 Seigr Imports
from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.helpers import is_senary
from src.crypto.hypha_crypt import HyphaCrypt
from src.logger.secure_logger import secure_logger
from src.crypto.alert_utils import trigger_alert  # ✅ Use centralized alerting
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
)
from src.seigr_protocol.compiled.integrity_pb2 import MonitoringCycleResult
from src.seigr_protocol.compiled.seed_dot_seigr_pb2 import IntegrityVerification
from src.crypto.helpers import decode_from_senary

logger = logging.getLogger(__name__)


# ===============================
# 🔑 **Primary Integrity Hashing**
# ===============================

def _get_hypha_crypt():
    """Lazy import HyphaCrypt to prevent circular dependency issues."""
    from src.crypto.hypha_crypt import HyphaCrypt
    return HyphaCrypt

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
        HyphaCrypt = _get_hypha_crypt()  # ✅ Lazy load HyphaCrypt
        HyphaCrypt = _get_hypha_crypt()
        hypha_crypt = HyphaCrypt(data=data, segment_id="integrity_verification")
  
        integrity_hash = hypha_crypt.HASH_SEIGR_SENARY(data, salt=salt)  

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Integrity",
            message=f"{SEIGR_CELL_ID_PREFIX} Generated integrity hash successfully.",
            log_data={"computed_hash": integrity_hash}
        )
        return integrity_hash
    except Exception as e:
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            category="Integrity",
            message=f"{SEIGR_CELL_ID_PREFIX} ❌ Integrity hash generation failed.",
            log_data={"error": str(e)},
            sensitive=False,
        )
        raise ValueError("Integrity hash generation failed.") from e


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
        log_data={"verifier_id": verifier_id, "status": status, "integrity_level": integrity_level},
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
        HyphaCrypt = _get_hypha_crypt()
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
            log_data={"layers": layers, "use_senary": use_senary},
        )

        return hierarchy
    except Exception as e:
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            category="Integrity",
            message=f"{SEIGR_CELL_ID_PREFIX} ❌ Hierarchical hash generation failed.",
            log_data={"error": str(e)},
            sensitive=False,
        )
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
            log_data={
                "cycle_id": cycle_id,
                "total_threats_detected": total_threats_detected,
                "new_threats_detected": new_threats_detected,
                "next_cycle_scheduled": next_cycle_date.isoformat(),
            },
        )

        return monitoring_cycle
    except Exception as e:
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            category="Monitoring",
            message=f"{SEIGR_CELL_ID_PREFIX} ❌ Monitoring cycle generation failed.",
            log_data={"error": str(e)},
            sensitive=False,
        )
        raise ValueError("Monitoring cycle failed.") from e

# ===============================
# ✅ **Seigr-Compliant Hash Verification**
# ===============================


def verify_hash(data: bytes, expected_hash: str, salt: Optional[str] = None) -> bool:
    """
    **Verifies if the provided data matches the expected hash.**

    Args:
        data (bytes): **Data to verify.**
        expected_hash (str): **Expected hash for comparison.**
        salt (str, optional): **Salt used during hashing.**

    Returns:
        bool: **True if the computed hash matches expected hash, False otherwise.**

    Raises:
        ValueError: **If the hash format is invalid.**
    """
    try:
        # ✅ Validate `expected_hash` format before comparing
        if not isinstance(expected_hash, str) or len(expected_hash) < 10:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_WARNING,
                category="Hash Verification",
                message=f"{SEIGR_CELL_ID_PREFIX} ❌ Invalid hash format: Expected valid hash string.",
                sensitive=False,
            )
            raise ValueError(f"{SEIGR_CELL_ID_PREFIX} ❌ Invalid hash format: Expected valid hash string.")

        # ✅ Compute actual hash
        HyphaCrypt = _get_hypha_crypt()
        hypha_crypt = HyphaCrypt(data=data, segment_id="integrity_verification")
        computed_hash = hypha_crypt.HASH_SEIGR_SENARY(data, salt=salt)

        # ✅ Compare hashes
        match = computed_hash == expected_hash

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO if match else AlertSeverity.ALERT_SEVERITY_WARNING,
            category="Integrity",
            message=f"{SEIGR_CELL_ID_PREFIX} Hash verification {'successful' if match else 'failed'}.",
            log_data={"expected_hash": expected_hash, "computed_hash": computed_hash, "match": match},
        )

        return match
    except Exception as e:
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            category="Hash Verification",
            message=f"{SEIGR_CELL_ID_PREFIX} ❌ Integrity verification failed.",
            log_data={"error": str(e)},
            sensitive=False,
        )
        raise ValueError(f"{SEIGR_CELL_ID_PREFIX} ❌ Integrity verification failed.") from e