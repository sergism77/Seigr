# src/crypto/protocol_integrity.py

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from src.crypto.constants import SEIGR_CELL_ID_PREFIX, SEIGR_VERSION
from src.crypto.hypha_crypt import HyphaCrypt
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertSeverity, AlertType
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorSeverity,
)
from src.seigr_protocol.compiled.integrity_pb2 import (
    IntegrityCheck,
    IntegrityReport,
    MonitoringSummary,
    VerificationStatus,
)

# Initialize logger
logger = logging.getLogger(__name__)


### ⚠️ Critical Alert Trigger ###


def _trigger_alert(message: str, severity: AlertSeverity) -> None:
    """
    Triggers an alert for critical protocol integrity issues.

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
        source_component="Protocol Integrity",
    )
    logger.warning(f"ALERT Triggered: {alert.message} | Severity: {severity.name}")


### 📊 Protocol Integrity Class ###


class ProtocolIntegrity:
    def __init__(self, data: bytes, segment_id: str, layers: int = 4, use_senary: bool = True):
        """
        Initialize ProtocolIntegrity for hierarchical integrity verification.

        Args:
            data (bytes): Data segment to monitor.
            segment_id (str): Unique segment identifier.
            layers (int): Depth of hierarchical verification.
            use_senary (bool): Use senary encoding in verification.
        """
        self.data = data
        self.segment_id = segment_id
        self.layers = layers
        self.use_senary = use_senary
        self.crypt_instance = HyphaCrypt(data, segment_id, hash_depth=layers, use_senary=use_senary)
        logger.info(f"{SEIGR_CELL_ID_PREFIX} ProtocolIntegrity initialized for {segment_id}")

    ### 🔍 Integrity Check ###

    def perform_integrity_check(self) -> IntegrityCheck:
        """
        Performs an integrity check using hierarchical hashing.

        Returns:
            IntegrityCheck: Results of the integrity check.
        """
        try:
            primary_hash = self.crypt_instance.compute_primary_hash()
            hierarchy = self.crypt_instance.compute_layered_hashes()

            integrity_check = IntegrityCheck(
                check_id=f"{self.segment_id}_check_{datetime.now(timezone.utc).isoformat()}",
                segment_id=self.segment_id,
                primary_hash=primary_hash,
                layers_verified=self.layers,
                timestamp=datetime.now(timezone.utc).isoformat(),
                senary_encoding=self.use_senary,
                metadata={
                    "verification_depth": self.layers,
                    "integrity_level": "standard",
                    "version": SEIGR_VERSION,
                },
            )

            logger.info(f"{SEIGR_CELL_ID_PREFIX} Integrity check completed: {primary_hash}")
            return integrity_check

        except Exception as e:
            self._log_error("integrity_check_fail", "Failed during integrity check.", e)
            raise ValueError("Integrity check failed.") from e

    ### 📝 Integrity Report ###

    def generate_integrity_report(self, reference_hierarchy: Dict[str, Any]) -> IntegrityReport:
        """
        Generates an integrity report comparing against a reference hash hierarchy.

        Args:
            reference_hierarchy (Dict): Reference hash hierarchy.

        Returns:
            IntegrityReport: Protocol Buffer Integrity Report.
        """
        try:
            results = self.crypt_instance.verify_integrity(
                reference_hierarchy, partial_depth=self.layers
            )
            status = (
                VerificationStatus.VERIFIED
                if results["status"] == "success"
                else VerificationStatus.COMPROMISED
            )

            integrity_report = IntegrityReport(
                report_id=f"{self.segment_id}_report_{datetime.now(timezone.utc).isoformat()}",
                segment_id=self.segment_id,
                status=status,
                failed_layers=results.get("failed_layers", []),
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={"status": results["status"]},
                metadata={"integrity_verification_depth": self.layers},
            )

            logger.info(
                f"{SEIGR_CELL_ID_PREFIX} Integrity report generated with status: {status.name}"
            )
            return integrity_report

        except Exception as e:
            self._log_error("integrity_report_fail", "Failed to generate integrity report.", e)
            raise ValueError("Failed to generate integrity report.") from e

    ### 📅 Monitoring Cycle ###

    def schedule_monitoring_cycle(
        self, cycle_interval_senary: str, threats_detected: int, new_threats: int
    ) -> MonitoringSummary:
        """
        Schedules a monitoring cycle using a senary interval.

        Args:
            cycle_interval_senary (str): Senary-formatted interval.
            threats_detected (int): Total detected threats.
            new_threats (int): Newly detected threats.

        Returns:
            MonitoringSummary: Monitoring summary object.
        """
        try:
            interval_days = int(cycle_interval_senary, 6)
            next_cycle_date = datetime.now(timezone.utc) + timedelta(days=interval_days)

            monitoring_summary = MonitoringSummary(
                summary_id=f"{self.segment_id}_summary_{datetime.now(timezone.utc).isoformat()}",
                segment_id=self.segment_id,
                completed_at=datetime.now(timezone.utc).isoformat(),
                total_threats_detected=threats_detected,
                new_threats_detected=new_threats,
                resolution_status="pending",
                next_cycle_scheduled=next_cycle_date.isoformat(),
            )

            logger.info(
                f"{SEIGR_CELL_ID_PREFIX} Next monitoring cycle scheduled for {next_cycle_date}"
            )
            return monitoring_summary

        except ValueError as e:
            self._log_error(
                "monitoring_schedule_fail",
                "Failed to parse senary interval for monitoring schedule.",
                e,
            )
            raise ValueError("Invalid senary interval format.") from e

    ### ⚠️ Structured Error Logging ###

    def _log_error(self, error_id: str, message: str, exception: Exception):
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_{error_id}",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Protocol Integrity",
            message=message,
            details=str(exception),
        )
        logger.error(f"{message}: {exception}")
