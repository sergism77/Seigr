import logging
from datetime import datetime, timezone, timedelta
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.hash_utils import hypha_hash, verify_hash
from src.crypto.encoding_utils import encode_to_senary, decode_from_senary, is_senary
from src.seigr_protocol.compiled.integrity_pb2 import IntegrityVerification, MonitoringCycleResult
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy

logger = logging.getLogger(__name__)

def generate_integrity_hash(data: bytes, salt: str = None, use_senary: bool = True) -> str:
    """
    Generates a primary integrity hash for the given data, optionally encoded in senary.
    """
    try:
        integrity_hash = hypha_hash(data, salt=salt, senary_output=use_senary)
        logger.info(f"Generated integrity hash: {integrity_hash} (senary: {use_senary})")
        return integrity_hash
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id="integrity_hash_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Integrity Verification",
            message="Failed to generate integrity hash.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise ValueError(error_log.message) from e

def verify_integrity(data: bytes, expected_hash: str, salt: str = None) -> bool:
    """
    Verifies the integrity of the given data against an expected hash.
    """
    try:
        use_senary = is_senary(expected_hash)
        match = verify_hash(data, expected_hash, salt=salt, senary_output=use_senary)
        logger.info(f"Integrity verification result: {'Match' if match else 'No Match'} for hash: {expected_hash}")
        return match
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id="integrity_verification_fail",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Integrity Verification",
            message="Integrity verification failed.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        raise ValueError(error_log.message) from e

def log_integrity_verification(status: str, verifier_id: str, integrity_level: str = "FULL", details: dict = None) -> IntegrityVerification:
    """
    Logs the result of an integrity verification process as a protocol buffer message.
    """
    verification_entry = IntegrityVerification(
        status=status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        verifier_id=verifier_id,
        integrity_level=integrity_level,
        details=details if details else {}
    )
    logger.info(f"Logged integrity verification: {verification_entry}")
    return verification_entry

def create_hierarchical_hashes(data: bytes, layers: int = 3, salt: str = None, use_senary: bool = True) -> dict:
    """
    Creates a hierarchy of hashes to provide additional integrity verification layers.
    """
    crypt_instance = HyphaCrypt(data, segment_id="segment", hash_depth=layers, use_senary=use_senary)
    hierarchy = crypt_instance.compute_layered_hashes()
    logger.info(f"Generated hierarchical hashes with {layers} layers.")
    return hierarchy

def calculate_senary_interval(interval_senary: str) -> timedelta:
    """
    Converts a senary interval string (e.g., "10" in senary representing 6 days) into a timedelta.
    """
    interval_days = int(interval_senary, 6)
    timedelta_interval = timedelta(days=interval_days)
    logger.debug(f"Calculated timedelta from senary interval {interval_senary}: {timedelta_interval}")
    return timedelta_interval

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

    logger.info(f"Generated monitoring cycle result with next cycle scheduled on: {monitoring_cycle.next_cycle_scheduled}")
    return monitoring_cycle

def verify_hierarchical_integrity(data: bytes, reference_hierarchy: dict, layers: int = 3, salt: str = None) -> bool:
    """
    Verifies integrity using a hierarchical hash structure.
    """
    generated_hierarchy = create_hierarchical_hashes(data, layers=layers, salt=salt)
    
    for layer in range(1, layers + 1):
        generated_hash = generated_hierarchy.get(f"Layer_{layer}")
        reference_hash = reference_hierarchy.get(f"Layer_{layer}")
        
        if generated_hash != reference_hash:
            logger.warning(f"Integrity verification failed at Layer {layer}")
            return False
    
    logger.info("Hierarchical integrity verified successfully.")
    return True

def encode_and_log_integrity(data: bytes, verifier_id: str, salt: str = None, use_senary: bool = True, integrity_level: str = "FULL") -> IntegrityVerification:
    """
    Generates a senary-encoded integrity hash, logs the verification, and returns the log entry.
    """
    integrity_hash = generate_integrity_hash(data, salt=salt, use_senary=use_senary)
    verification_status = "SUCCESS" if integrity_hash else "FAILED"
    verification_log = log_integrity_verification(
        status=verification_status,
        verifier_id=verifier_id,
        integrity_level=integrity_level,
        details={"integrity_hash": integrity_hash}
    )
    logger.info(f"Encoded and logged integrity for verifier {verifier_id} with status {verification_status}")
    return verification_log
