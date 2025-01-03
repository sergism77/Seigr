import logging
import os
import uuid
import json
from cryptography.fernet import Fernet
from datetime import datetime, timezone, timedelta

from src.crypto.encoding_utils import encode_to_senary
from src.crypto.hash_utils import hypha_hash
from src.crypto.key_derivation import generate_salt
from src.crypto.hypha_crypt import HyphaCrypt  # Seigr's secure encryption
from src.crypto.constants import SEIGR_CELL_ID_PREFIX, DEFAULT_RETENTION_PERIOD_DAYS

from src.seigr_protocol.compiled.audit_logging_pb2 import (
    AuditLogEntry,
    LogLevel,
    LogCategory,
)
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorSeverity,
    ErrorResolutionStrategy,
)
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertType, AlertSeverity


# Initialize the compliance logger
logger = logging.getLogger("compliance_auditing")
logging.basicConfig(
    filename="compliance_audit.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


### 🛡️ Alert Triggering for Critical Compliance Failures ###

def _trigger_alert(message: str, severity: AlertSeverity) -> None:
    """
    Triggers an alert for critical failures in compliance operations.

    Args:
        message (str): Description of the issue.
        severity (AlertSeverity): The severity level of the alert.

    Returns:
        None
    """
    alert = Alert(
        alert_id=f"{SEIGR_CELL_ID_PREFIX}_{uuid.uuid4()}",
        message=message,
        type=AlertType.ALERT_TYPE_DATA,
        severity=severity,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_component="compliance_auditing",
    )
    logger.warning(
        f"Alert triggered: {alert.message} with severity {alert.severity.name}"
    )


### 📊 Compliance Auditor Class with Retention and Reporting ###

class ComplianceAuditor:
    def __init__(self, retention_period_days: int = DEFAULT_RETENTION_PERIOD_DAYS):
        """
        Initializes ComplianceAuditor with an optional retention period for logs.

        Args:
            retention_period_days (int): Retention period for logs in days.
        """
        self.retention_period = timedelta(days=retention_period_days)

    ### 📥 Audit Event Recording ###

    def record_audit_event(
        self,
        severity: LogLevel,
        category: LogCategory,
        message: str,
        metadata: dict = None,
    ) -> AuditLogEntry:
        """
        Records an audit event, ensuring it complies with Seigr standards.

        Args:
            severity (LogLevel): Severity level of the audit event.
            category (LogCategory): Category of the audit event.
            message (str): Description of the event.
            metadata (dict): Optional metadata for additional context.

        Returns:
            AuditLogEntry: Structured audit log entry.
        """
        try:
            entry_id = f"{SEIGR_CELL_ID_PREFIX}_audit_{uuid.uuid4()}"
            audit_entry = AuditLogEntry(
                entry_id=entry_id,
                severity=severity,
                category=category,
                message=message,
                timestamp=datetime.now(timezone.utc).isoformat(),
                metadata=metadata or {"protocol": "Seigr"},
            )
            logger.info(f"[{severity.name}] {category.name}: {audit_entry.message}")
            return audit_entry
        except Exception as e:
            self._log_and_alert_error(
                "Failed to record audit event",
                e,
                "Compliance Auditor",
                ErrorSeverity.ERROR_SEVERITY_HIGH,
                AlertSeverity.ALERT_SEVERITY_HIGH,
            )

    ### 📤 Audit Log Retrieval ###

    def retrieve_audit_logs(
        self, start_date: datetime = None, end_date: datetime = None
    ) -> list:
        """
        Retrieves audit logs within a specified date range.

        Args:
            start_date (datetime): Start date for filtering logs.
            end_date (datetime): End date for filtering logs.

        Returns:
            list: Filtered list of audit log entries.
        """
        try:
            logs = []
            with open("compliance_audit.log", "r") as log_file:
                for line in log_file:
                    log_entry = json.loads(line)
                    log_time = datetime.fromisoformat(
                        log_entry.get("timestamp").replace("Z", "+00:00")
                    )
                    if (not start_date or log_time >= start_date) and (
                        not end_date or log_time <= end_date
                    ):
                        logs.append(log_entry)
            logger.info(f"Retrieved {len(logs)} logs from compliance audit file.")
            return logs
        except Exception as e:
            self._log_and_alert_error(
                "Failed to retrieve audit logs",
                e,
                "Compliance Auditor",
                ErrorSeverity.ERROR_SEVERITY_MEDIUM,
                AlertSeverity.ALERT_SEVERITY_MEDIUM,
            )

    ### 🧹 Retention Policy Enforcement ###

    def enforce_retention_policy(self):
        """
        Enforces log retention policy by removing logs older than the specified retention period.
        """
        try:
            current_time = datetime.now(timezone.utc)
            logs_to_keep = []
            with open("compliance_audit.log", "r") as log_file:
                for line in log_file:
                    log_entry = json.loads(line)
                    log_time = datetime.fromisoformat(
                        log_entry.get("timestamp").replace("Z", "+00:00")
                    )
                    if current_time - log_time <= self.retention_period:
                        logs_to_keep.append(line)

            with open("compliance_audit.log", "w") as log_file:
                log_file.writelines(logs_to_keep)

            logger.info(
                f"Retention policy enforced. Logs older than {self.retention_period.days} days removed."
            )
        except Exception as e:
            self._log_and_alert_error(
                "Failed to enforce retention policy",
                e,
                "Compliance Auditor",
                ErrorSeverity.ERROR_SEVERITY_HIGH,
                AlertSeverity.ALERT_SEVERITY_HIGH,
            )

    ### ⚠️ Internal Method to Log and Alert on Errors ###

    def _log_and_alert_error(
        self,
        message: str,
        exception: Exception,
        component: str,
        error_severity: ErrorSeverity,
        alert_severity: AlertSeverity,
    ):
        """
        Logs an error and triggers an alert for critical issues.
        """
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_{uuid.uuid4()}",
            severity=error_severity,
            component=component,
            message=message,
            details=str(exception),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE,
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        _trigger_alert(message, alert_severity)
        raise ValueError(message)
