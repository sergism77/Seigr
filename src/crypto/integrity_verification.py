import logging
from datetime import datetime, timezone, timedelta

from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.hash_utils import hypha_hash, verify_hash
from src.crypto.encoding_utils import encode_to_senary, decode_from_senary, is_senary
from src.crypto.constants import SEIGR_CELL_ID_PREFIX, SEIGR_VERSION

from src.seigr_protocol.compiled.integrity_pb2 import (
    IntegrityVerification,
    MonitoringCycleResult,
)
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorSeverity,
    ErrorResolutionStrategy,
)
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertType, AlertSeverity

logger = logging.getLogger(__name__)


### 🛡️ Alert Trigger for Critical Integrity Issues ###

def _trigger_alert(message: str, severity: AlertSeverity) -> None:
    """
    Triggers an alert for critical failures in integrity verification.

    Args:
        message (str): Description of the issue.
        severity (AlertSeverity): Severity level of the alert.
    """
    alert = Alert(
        alert_id=f"{SEIGR_CELL_ID_PREFIX}_alert_{datetime.now(timezone.utc).isoformat()}",
        message=message,
        type=AlertType.ALERT_TYPE_SECURITY,
        severity=severity,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_component="integrity_verification",
    )
    logger.warning(f"Alert triggered: {alert.message} with severity {severity.name}")


### 🔑 Integrity Hash Generation ###

def generate_integrity_hash(
    data: bytes, salt: str = None, use_senary: bool = True
) -> str:
    """
    Generates a primary integrity hash for the given data, optionally encoded in senary.

    Args:
        data (bytes): Data to hash.
        salt (str, optional): Salt for hashing.
        use_senary (bool): Whether to return the hash in senary format.

    Returns:
        str: Generated integrity hash.
    """
    try:
        integrity_hash = hypha_hash(data, salt=salt, senary_output=use_senary)
        logger.info(
            f"{SEIGR_CELL_ID_PREFIX} Generated integrity hash: {integrity_hash} (senary: {use_senary})"
        )
        return integrity_hash
    except Exception as e:
        _log_error(
            f"{SEIGR_CELL_ID_PREFIX}_integrity_hash_fail",
            "Failed to generate integrity hash",
            e,
        )
        raise ValueError("Integrity hash generation failed.") from e


### ✅ Integrity Verification ###

def verify_integrity(data: bytes, expected_hash: str, salt: str = None) -> bool:
    """
    Verifies the integrity of the given data against an expected hash.

    Args:
        data (bytes): Data to verify.
        expected_hash (str): Expected hash for verification.
        salt (str, optional): Salt used during hashing.

    Returns:
        bool: True if verification succeeds, False otherwise.
    """
    try:
        use_senary = is_senary(expected_hash)
        match = verify_hash(data, expected_hash, salt=salt, senary_output=use_senary)
        logger.info(
            f"{SEIGR_CELL_ID_PREFIX} Integrity verification result: {'Match' if match else 'No Match'}"
        )
        return match
    except Exception as e:
        _log_error(
            f"{SEIGR_CELL_ID_PREFIX}_integrity_verification_fail",
            "Integrity verification failed",
            e,
        )
        raise ValueError("Integrity verification failed.") from e


### 📊 Logging Integrity Verification ###

def log_integrity_verification(
    status: str, verifier_id: str, integrity_level: str = "FULL", details: dict = None
) -> IntegrityVerification:
    """
    Logs the result of an integrity verification process as a protocol buffer message.

    Args:
        status (str): Verification status.
        verifier_id (str): Identifier of the verifier.
        integrity_level (str): Level of integrity verification.
        details (dict, optional): Additional details.

    Returns:
        IntegrityVerification: Protocol buffer log entry.
    """
    verification_entry = IntegrityVerification(
        status=status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        verifier_id=verifier_id,
        integrity_level=integrity_level,
        details=details or {},
    )
    logger.info(
        f"{SEIGR_CELL_ID_PREFIX} Logged integrity verification: {verification_entry}"
    )
    return verification_entry


### 🏗️ Hierarchical Hashing ###

def create_hierarchical_hashes(
    data: bytes, layers: int = 3, salt: str = None, use_senary: bool = True
) -> dict:
    """
    Creates a hierarchy of hashes to provide additional integrity verification layers.

    Args:
        data (bytes): Data to hash.
        layers (int): Number of hierarchical layers.
        salt (str, optional): Salt for hashing.
        use_senary (bool): Whether to use senary encoding.

    Returns:
        dict: Hierarchical hash layers.
    """
    try:
        crypt_instance = HyphaCrypt(
            data,
            segment_id=f"{SEIGR_CELL_ID_PREFIX}_segment",
            hash_depth=layers,
            use_senary=use_senary,
        )
        hierarchy = crypt_instance.compute_layered_hashes()
        logger.info(
            f"{SEIGR_CELL_ID_PREFIX} Generated hierarchical hashes with {layers} layers."
        )
        return hierarchy
    except Exception as e:
        _log_error(
            f"{SEIGR_CELL_ID_PREFIX}_hierarchical_hash_fail",
            "Failed to create hierarchical hashes",
            e,
        )
        raise ValueError("Hierarchical hashing failed.") from e


### 📅 Monitoring Cycle Generation ###

def generate_monitoring_cycle(
    cycle_id: str,
    segments_status: list,
    total_threats_detected: int,
    new_threats_detected: int,
    interval_senary: str = "10",
) -> MonitoringCycleResult:
    """
    Generates a monitoring cycle result.

    Returns:
        MonitoringCycleResult: Monitoring cycle protocol buffer message.
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
        return monitoring_cycle
    except Exception as e:
        _log_error(
            f"{SEIGR_CELL_ID_PREFIX}_monitoring_cycle_fail",
            "Failed to generate monitoring cycle",
            e,
        )
        raise ValueError("Monitoring cycle failed.") from e


### ⚠️ Internal Error Logging ###

def _log_error(error_id, message, exception):
    error_log = ErrorLogEntry(
        error_id=error_id,
        severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
        component="Integrity Verification",
        message=message,
        details=str(exception),
    )
    logger.error(f"{message}: {exception}")
