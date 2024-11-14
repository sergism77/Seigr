import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from src.crypto.hypha_crypt import HyphaCrypt
from src.crypto.integrity_verification import verify_integrity
from src.seigr_protocol.compiled.integrity_pb2 import IntegrityCheck, IntegrityReport, MonitoringSummary, VerificationStatus
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy
from src.crypto.constants import SEIGR_CELL_ID_PREFIX

# Initialize logger
logger = logging.getLogger(__name__)

class ProtocolIntegrity:
    def __init__(self, data: bytes, segment_id: str, layers: int = 4, use_senary: bool = True):
        """
        Initialize ProtocolIntegrity for hierarchical integrity verification.

        Args:
            data (bytes): The data segment to be monitored.
            segment_id (str): Unique identifier for the data segment.
            layers (int): Depth of hierarchical integrity verification.
            use_senary (bool): Option to use senary encoding in verification.
        """
        self.data = data
        self.segment_id = segment_id
        self.layers = layers
        self.use_senary = use_senary
        self.crypt_instance = HyphaCrypt(data, segment_id, hash_depth=layers, use_senary=use_senary)

    def perform_integrity_check(self) -> IntegrityCheck:
        """
        Performs a comprehensive integrity check on the data segment using hierarchical hashing.
        
        Returns:
            IntegrityCheck: A protocol buffer message with check results.
        """
        try:
            primary_hash = self.crypt_instance.compute_primary_hash()
            hierarchy = self.crypt_instance.compute_layered_hashes()
            
            # Build integrity check message with hierarchical details
            integrity_check = IntegrityCheck(
                check_id=f"{self.segment_id}_check_{datetime.now(timezone.utc).isoformat()}",
                segment_id=self.segment_id,
                primary_hash=primary_hash,
                layers_verified=self.layers,
                timestamp=datetime.now(timezone.utc).isoformat(),
                senary_encoding=self.use_senary,
                metadata={"verification_depth": self.layers, "integrity_level": "standard"}
            )
            logger.info(f"Integrity check performed on segment {self.segment_id} with primary hash: {primary_hash}")
            return integrity_check
        except Exception as e:
            self._log_error("integrity_check_fail", "Failed to perform integrity check", e)

    def generate_integrity_report(self, reference_hierarchy: Dict[str, Any]) -> IntegrityReport:
        """
        Compares current integrity data against a reference hierarchy and generates a report.
        
        Args:
            reference_hierarchy (dict): Reference hash hierarchy for comparison.

        Returns:
            IntegrityReport: Protocol buffer message containing the integrity verification results.
        """
        results = self.crypt_instance.verify_integrity(reference_hierarchy, partial_depth=self.layers)
        report_status = VerificationStatus.VERIFIED if results["status"] == "success" else VerificationStatus.COMPROMISED
        integrity_report = IntegrityReport(
            report_id=f"{self.segment_id}_report_{datetime.now(timezone.utc).isoformat()}",
            segment_id=self.segment_id,
            status=report_status,
            failed_layers=results["failed_layers"],
            timestamp=datetime.now(timezone.utc).isoformat(),
            details={"status": results["status"]},
            metadata={"integrity_verification_depth": self.layers}
        )
        logger.info(f"Generated integrity report for segment {self.segment_id} with status: {report_status.name}")
        return integrity_report

    def schedule_monitoring_cycle(
        self, cycle_interval_senary: str, threats_detected: int, new_threats: int
    ) -> MonitoringSummary:
        """
        Sets up a monitoring cycle with dynamically scheduled intervals based on senary format.

        Args:
            cycle_interval_senary (str): Interval for the next monitoring cycle in senary format.
            threats_detected (int): Total number of threats detected in this cycle.
            new_threats (int): Number of new threats detected since the last cycle.

        Returns:
            MonitoringSummary: A summary message with the scheduled next cycle.
        """
        try:
            current_time = datetime.now(timezone.utc)
            next_cycle_interval = self._senary_to_timedelta(cycle_interval_senary)
            next_cycle_date = current_time + next_cycle_interval

            monitoring_summary = MonitoringSummary(
                summary_id=f"{self.segment_id}_summary_{datetime.now(timezone.utc).isoformat()}",
                segment_id=self.segment_id,
                completed_at=current_time.isoformat(),
                total_threats_detected=threats_detected,
                new_threats_detected=new_threats,
                resolution_status="pending",
                next_cycle_scheduled=next_cycle_date.isoformat(),
                threat_summary={"integrity": threats_detected}
            )

            logger.info(f"Scheduled next monitoring cycle on {next_cycle_date} for segment {self.segment_id}")
            return monitoring_summary
        except Exception as e:
            self._log_error("monitoring_schedule_fail", "Failed to schedule monitoring cycle", e)

    def _senary_to_timedelta(self, interval_senary: str) -> timedelta:
        """
        Converts a senary interval string to a timedelta.

        Args:
            interval_senary (str): Senary interval format.

        Returns:
            timedelta: Calculated interval.
        """
        try:
            interval_days = int(interval_senary, 6)
            logger.debug(f"Converted senary interval {interval_senary} to {interval_days} days.")
            return timedelta(days=interval_days)
        except ValueError as e:
            self._log_error("interval_conversion_fail", "Failed to convert senary interval", e)

    def _log_error(self, error_id: str, message: str, exception: Exception):
        """Logs an error using a structured protocol buffer entry."""
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_{error_id}",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Protocol Integrity",
            message=message,
            details=str(exception),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
        )
        logger.error(f"{message}: {exception}")
