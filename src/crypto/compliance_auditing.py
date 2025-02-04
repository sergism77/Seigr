"""
📌 **Seigr Compliance Auditing Module**
Provides structured audit logging, retention enforcement, and alerting for compliance operations.
Fully aligned with **Seigr security, retention, and structured logging policies**.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

# 🔐 Seigr Imports
from src.crypto.constants import DEFAULT_RETENTION_PERIOD_DAYS, SEIGR_CELL_ID_PREFIX
from src.crypto.alert_utils import trigger_alert
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity, AlertType
from src.seigr_protocol.compiled.audit_logging_pb2 import AuditLogEntry, LogCategory, LogLevel
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity  # ✅ Correct import
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
)  # ✅ Keep only necessary imports
from src.logger.secure_logger import secure_logger


# ===============================
# 📊 **Compliance Auditor Class**
# ===============================
class ComplianceAuditor:
    """
    **Manages compliance audit logging, retention policies, and structured alerts.**
    """

    def __init__(self, retention_period_days: int = DEFAULT_RETENTION_PERIOD_DAYS):
        """
        **Initializes the Compliance Auditor with a structured log retention policy.**

        Args:
            retention_period_days (int, optional): Number of days to retain logs (default: from constants).
        """
        self.retention_period = timedelta(days=retention_period_days)
        self.log_file = "compliance_audit.log"

    # ===============================
    # 📥 **Audit Event Recording**
    # ===============================
    def record_audit_event(
        self, severity: LogLevel, category: LogCategory, message: str, metadata: dict = None
    ) -> AuditLogEntry:
        """
        **Records an audit event with Seigr-compliant structured logging.**

        Args:
            severity (LogLevel): Severity level of the event.
            category (LogCategory): Category of the event.
            message (str): Description of the event.
            metadata (dict, optional): Additional metadata.

        Returns:
            AuditLogEntry: The structured audit log entry.
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
            secure_logger.log_audit_event(
                severity=severity, category=category.name, message=message, log_data=audit_entry
            )
            return audit_entry
        except Exception as e:
            trigger_alert(
                message="Failed to record audit event",
                severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                alert_type=AlertType.ALERT_TYPE_COMPLIANCE,  # ✅ Properly classified
                source_component="compliance_auditing",
            )

    # ===============================
    # 📤 **Audit Log Retrieval**
    # ===============================
    def retrieve_audit_logs(self, start_date: datetime = None, end_date: datetime = None) -> list:
        """
        **Retrieves audit logs within a specified date range.**

        Args:
            start_date (datetime, optional): Start date for filtering logs.
            end_date (datetime, optional): End date for filtering logs.

        Returns:
            list: Filtered list of audit log entries.
        """
        try:
            logs = []
            with open(self.log_file, "r", encoding="utf-8") as log_file:
                for line in log_file:
                    log_entry = json.loads(line)
                    log_time = datetime.fromisoformat(
                        log_entry.get("timestamp").replace("Z", "+00:00")
                    )
                    if (not start_date or log_time >= start_date) and (
                        not end_date or log_time <= end_date
                    ):
                        logs.append(log_entry)

            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Audit Log Retrieval",
                message=f"✅ Retrieved {len(logs)} logs from compliance audit file.",
                log_data={"log_count": len(logs)},
            )
            return logs
        except Exception as e:
            trigger_alert(
                message="Failed to retrieve audit logs",
                severity=AlertSeverity.ALERT_SEVERITY_MEDIUM,
                alert_type=AlertType.ALERT_TYPE_COMPLIANCE,  # ✅ Properly classified
                source_component="compliance_auditing",
            )

    # ===============================
    # 🧹 **Retention Policy Enforcement**
    # ===============================
    def enforce_retention_policy(self):
        """
        **Enforces log retention policy by removing logs older than the configured retention period.**
        """
        try:
            current_time = datetime.now(timezone.utc)
            logs_to_keep = []

            with open(self.log_file, "r", encoding="utf-8") as log_file:
                for line in log_file:
                    log_entry = json.loads(line)
                    log_time = datetime.fromisoformat(
                        log_entry.get("timestamp").replace("Z", "+00:00")
                    )
                    if current_time - log_time <= self.retention_period:
                        logs_to_keep.append(line)

            with open(self.log_file, "w", encoding="utf-8") as log_file:
                log_file.writelines(logs_to_keep)

            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Retention Policy",
                message=f"✅ Retention policy enforced. Logs older than {self.retention_period.days} days removed.",
            )
        except Exception as e:
            trigger_alert(
                message="Failed to enforce retention policy",
                severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                alert_type=AlertType.ALERT_TYPE_COMPLIANCE,  # ✅ Properly classified
                source_component="compliance_auditing",
            )

    # ===============================
    # ⚠️ **Internal Method: Log & Alert on Errors**
    # ===============================
    def _log_and_alert_error(
        self,
        error_message: str,  # ✅ Renamed to avoid conflicts
        exception: Exception,
        component: str,
        error_severity: AlertSeverity,
        alert_severity: AlertSeverity,
    ):
        """
        **Logs an error and triggers an alert for critical issues.**

        Args:
            error_message (str): Error message.
            exception (Exception): Exception details.
            component (str): Component where the error occurred.
            error_severity (AlertSeverity): Severity of the error.
            alert_severity (AlertSeverity): Severity of the triggered alert.

        Raises:
            ValueError: After logging and alerting.
        """
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_{uuid.uuid4()}",
            severity=error_severity,
            component=component,
            message=error_message,
            details=str(exception),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE,
        )

        # ✅ Log structured error using SecureLogger
        secure_logger.log_audit_event(
            severity=error_severity,
            category="Compliance Auditing",
            message=f"❌ {error_message}: {exception}",
            log_data=error_log,
        )

        # ✅ Correctly triggers an alert with full Seigr compliance
        trigger_alert(
            message=error_message,
            severity=alert_severity,
            alert_type=AlertType.ALERT_TYPE_COMPLIANCE,  # 🔎 Proper alert classification
            source_component="compliance_auditing",  # 📍 Clearly specifies the module
        )

        raise ValueError(error_message)
