import logging
from datetime import datetime, timezone, timedelta
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.hash_utils import hypha_hash, verify_hash
from src.crypto.encoding_utils import encode_to_senary, decode_from_senary, is_senary
from src.seigr_protocol.compiled.integrity_pb2 import IntegrityVerification, MonitoringCycleResult
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy
from src.crypto.constants import SEIGR_CELL_ID_PREFIX, SEIGR_VERSION

logger = logging.getLogger(__name__)

### Integrity Hash Generation ###

def generate_integrity_hash(data: bytes, salt: str = None, use_senary: bool = True) -> str:
    """
    Generates a primary integrity hash for the given data, optionally encoded in senary.
    """
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Starting integrity hash generation for data length {len(data)}")
    try:
        integrity_hash = hypha_hash(data, salt=salt, senary_output=use_senary)
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Generated integrity hash: {integrity_hash} (senary: {use_senary})")
        return integrity_hash
    except Exception as e:
        _log_error(f"{SEIGR_CELL_ID_PREFIX}_integrity_hash_fail", "Failed to generate integrity hash", e)
        raise ValueError("Integrity hash generation failed.") from e

### Integrity Verification ###

def verify_integrity(data: bytes, expected_hash: str, salt: str = None) -> bool:
    """
    Verifies the integrity of the given data against an expected hash.
    """
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Starting integrity verification for data length {len(data)}")
    try:
        use_senary = is_senary(expected_hash)
        match = verify_hash(data, expected_hash, salt=salt, senary_output=use_senary)
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Integrity verification result: {'Match' if match else 'No Match'} for hash: {expected_hash}")
        return match
    except Exception as e:
        _log_error(f"{SEIGR_CELL_ID_PREFIX}_integrity_verification_fail", "Integrity verification failed", e)
        raise ValueError("Integrity verification failed.") from e

def log_integrity_verification(status: str, verifier_id: str, integrity_level: str = "FULL", details: dict = None) -> IntegrityVerification:
    """
    Logs the result of an integrity verification process as a protocol buffer message.
    """
    verification_entry = IntegrityVerification(
        status=status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        verifier_id=verifier_id,
        integrity_level=integrity_level,
        details=details or {}
    )
    logger.info(f"{SEIGR_CELL_ID_PREFIX} Logged integrity verification: {verification_entry}")
    return verification_entry

### Hierarchical Hashing ###

def create_hierarchical_hashes(data: bytes, layers: int = 3, salt: str = None, use_senary: bool = True) -> dict:
    """
    Creates a hierarchy of hashes to provide additional integrity verification layers.
    """
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Starting hierarchical hash generation with {layers} layers")
    crypt_instance = HyphaCrypt(data, segment_id=f"{SEIGR_CELL_ID_PREFIX}_segment", hash_depth=layers, use_senary=use_senary)
    hierarchy = crypt_instance.compute_layered_hashes()
    logger.info(f"{SEIGR_CELL_ID_PREFIX} Generated hierarchical hashes with {layers} layers.")
    return hierarchy

def calculate_senary_interval(interval_senary: str) -> timedelta:
    """
    Converts a senary interval string (e.g., "10" in senary representing 6 days) into a timedelta.
    """
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Converting senary interval {interval_senary} to timedelta")
    try:
        interval_days = int(interval_senary, 6)
        timedelta_interval = timedelta(days=interval_days)
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} Calculated timedelta: {timedelta_interval}")
        return timedelta_interval
    except ValueError as e:
        _log_error(f"{SEIGR_CELL_ID_PREFIX}_interval_conversion_fail", "Failed to convert senary interval", e)
        raise ValueError("Invalid senary interval") from e

### Monitoring Cycle Generation ###

def generate_monitoring_cycle(
    cycle_id: str,
    segments_status: list,
    total_threats_detected: int,
    new_threats_detected: int,
    interval_senary: str = "10"
) -> MonitoringCycleResult:
    """
    Generates a monitoring cycle result with a dynamically calculated next cycle date based on senary intervals.
    """
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Generating monitoring cycle for cycle ID {cycle_id}")
    try:
        current_time = datetime.now(timezone.utc)
        next_cycle_interval = calculate_senary_interval(interval_senary)
        next_cycle_date = current_time + next_cycle_interval

        monitoring_cycle = MonitoringCycleResult(
            cycle_id=cycle_id,
            segments_status=segments_status,
            completed_at=current_time.isoformat(),
            total_threats_detected=total_threats_detected,
            new_threats_detected=new_threats_detected,
            resolution_status="pending",
            threat_summary={"integrity": total_threats_detected},
            next_cycle_scheduled=next_cycle_date.isoformat()
        )

        logger.info(f"{SEIGR_CELL_ID_PREFIX} Generated monitoring cycle result with next cycle scheduled on: {monitoring_cycle.next_cycle_scheduled}")
        return monitoring_cycle
    except Exception as e:
        _log_error(f"{SEIGR_CELL_ID_PREFIX}_monitoring_cycle_fail", "Failed to generate monitoring cycle", e)
        raise ValueError("Monitoring cycle generation failed.") from e

### Hierarchical Integrity Verification ###

def verify_hierarchical_integrity(data: bytes, reference_hierarchy: dict, layers: int = 3, salt: str = None) -> bool:
    """
    Verifies integrity using a hierarchical hash structure.
    """
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Starting hierarchical integrity verification for data length {len(data)}")
    try:
        generated_hierarchy = create_hierarchical_hashes(data, layers=layers, salt=salt)
        
        for layer in range(1, layers + 1):
            generated_hash = generated_hierarchy.get(f"Layer_{layer}")
            reference_hash = reference_hierarchy.get(f"Layer_{layer}")
            
            if generated_hash != reference_hash:
                logger.warning(f"{SEIGR_CELL_ID_PREFIX} Integrity verification failed at Layer {layer}")
                return False
        
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Hierarchical integrity verified successfully.")
        return True
    except Exception as e:
        _log_error(f"{SEIGR_CELL_ID_PREFIX}_hierarchical_verification_fail", "Failed hierarchical integrity verification", e)
        raise ValueError("Hierarchical integrity verification failed.") from e

def encode_and_log_integrity(data: bytes, verifier_id: str, salt: str = None, use_senary: bool = True, integrity_level: str = "FULL") -> IntegrityVerification:
    """
    Generates a senary-encoded integrity hash, logs the verification, and returns the log entry.
    """
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Starting encoding and logging of integrity for verifier {verifier_id}")
    try:
        integrity_hash = generate_integrity_hash(data, salt=salt, use_senary=use_senary)
        verification_status = "SUCCESS" if integrity_hash else "FAILED"
        verification_log = log_integrity_verification(
            status=verification_status,
            verifier_id=verifier_id,
            integrity_level=integrity_level,
            details={"integrity_hash": integrity_hash}
        )
        logger.info(f"{SEIGR_CELL_ID_PREFIX} Encoded and logged integrity for verifier {verifier_id} with status {verification_status}")
        return verification_log
    except Exception as e:
        _log_error(f"{SEIGR_CELL_ID_PREFIX}_encode_log_integrity_fail", "Failed to encode and log integrity", e)
        raise ValueError("Integrity encoding and logging failed.") from e

### Helper Function for Error Logging ###

def _log_error(error_id, message, exception):
    """Logs an error using a structured protocol buffer entry."""
    error_log = ErrorLogEntry(
        error_id=error_id,
        severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
        component="Integrity Verification",
        message=message,
        details=str(exception),
        resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE
    )
    logger.error(f"{message}: {exception}")
