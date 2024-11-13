import logging
import os
import json
from cryptography.fernet import Fernet
from datetime import datetime, timezone, timedelta
from src.crypto.encoding_utils import encode_to_senary
from src.crypto.hash_utils import hypha_hash
from src.crypto.key_derivation import generate_salt
from src.seigr_protocol.compiled.audit_logging_pb2 import AuditLogEntry, LogSeverity, LogCategory
from src.seigr_protocol.compiled.error_handling_pb2 import ErrorLogEntry, ErrorSeverity, ErrorResolutionStrategy

# Initialize the compliance logger
logger = logging.getLogger("compliance_auditing")
logging.basicConfig(
    filename='compliance_audit.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class ComplianceAuditor:
    def __init__(self, retention_period_days: int = 90):
        """
        Initializes ComplianceAuditor with an optional retention period for logs.

        Args:
            retention_period_days (int): Retention period for logs in days. Defaults to 90 days.
        """
        self.retention_period = timedelta(days=retention_period_days)

    def record_audit_event(self, severity: LogSeverity, category: LogCategory, message: str, metadata: dict = None) -> AuditLogEntry:
        """
        Records an audit event, ensuring it complies with Seigr standards.

        Args:
            severity (LogSeverity): Severity level of the audit event.
            category (LogCategory): Category of the audit event.
            message (str): Description of the event.
            metadata (dict): Optional metadata for additional context.

        Returns:
            AuditLogEntry: Structured audit log entry.
        """
        try:
            entry_id = f"audit_{datetime.now(timezone.utc).isoformat()}"
            audit_entry = AuditLogEntry(
                entry_id=entry_id,
                severity=severity,
                category=category,
                message=message,
                timestamp=datetime.now(timezone.utc).isoformat(),
                metadata=metadata or {}
            )
            logger.info(f"[{severity.name}] {category.name}: {audit_entry.message}")
            return audit_entry
        except Exception as e:
            error_log = ErrorLogEntry(
                error_id="audit_event_fail",
                severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
                component="Compliance Auditor",
                message="Failed to record audit event.",
                details=str(e),
                resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_LOG_AND_CONTINUE
            )
            logger.error(f"{error_log.message}: {error_log.details}")
            raise ValueError(error_log.message)

    def retrieve_audit_logs(self, start_date: datetime = None, end_date: datetime = None) -> list:
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
                    log_time = datetime.fromisoformat(log_entry.get("timestamp").replace("Z", "+00:00"))
                    if (not start_date or log_time >= start_date) and (not end_date or log_time <= end_date):
                        logs.append(log_entry)
            logger.info(f"Retrieved {len(logs)} logs from compliance audit file.")
            return logs
        except Exception as e:
            error_log = ErrorLogEntry(
                error_id="log_retrieval_fail",
                severity=ErrorSeverity.ERROR_SEVERITY_MEDIUM,
                component="Compliance Auditor",
                message="Failed to retrieve audit logs.",
                details=str(e),
                resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_RETRY
            )
            logger.error(f"{error_log.message}: {error_log.details}")
            raise ValueError(error_log.message)

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
                    log_time = datetime.fromisoformat(log_entry.get("timestamp").replace("Z", "+00:00"))
                    if current_time - log_time <= self.retention_period:
                        logs_to_keep.append(line)
            
            # Write only retained logs back to the file
            with open("compliance_audit.log", "w") as log_file:
                log_file.writelines(logs_to_keep)

            logger.info(f"Retention policy enforced. Logs older than {self.retention_period.days} days removed.")
        except Exception as e:
            error_log = ErrorLogEntry(
                error_id="retention_enforcement_fail",
                severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
                component="Compliance Auditor",
                message="Failed to enforce retention policy.",
                details=str(e),
                resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE
            )
            logger.error(f"{error_log.message}: {error_log.details}")
            raise ValueError(error_log.message)

    def generate_compliance_report(self, start_date: datetime, end_date: datetime, severity_filter: LogSeverity = None) -> dict:
        """
        Generates a compliance report for a specified period and optional severity level.

        Args:
            start_date (datetime): The start date for the report.
            end_date (datetime): The end date for the report.
            severity_filter (LogSeverity, optional): Filter for specific severity.

        Returns:
            dict: Summary report of audit events within the given period.
        """
        logs = self.retrieve_audit_logs(start_date=start_date, end_date=end_date)
        report = {
            "total_events": 0,
            "severities": {severity.name: 0 for severity in LogSeverity},
            "details": []
        }

        for log_entry in logs:
            severity = log_entry.get("severity")
            if not severity_filter or severity == severity_filter.name:
                report["total_events"] += 1
                report["severities"][severity] += 1
                report["details"].append(log_entry)

        logger.info(f"Compliance report generated from {start_date} to {end_date}")
        return report

    def secure_archive_logs(self, archive_name: str = None):
        """
        Archives audit logs into a secure encrypted file for long-term storage.

        Args:
            archive_name (str): Name of the archive file. Defaults to timestamp-based naming.
        """
        archive_name = archive_name or f"compliance_archive_{datetime.now(timezone.utc).isoformat()}.enc"
        try:
            with open("compliance_audit.log", "rb") as log_file:
                log_data = log_file.read()

            # Generate an encryption key for archiving
            encryption_key = Fernet.generate_key()
            fernet = Fernet(encryption_key)
            encrypted_data = fernet.encrypt(log_data)

            with open(archive_name, "wb") as archive_file:
                archive_file.write(encrypted_data)

            logger.info(f"Audit logs archived to {archive_name} with encryption.")
            return archive_name, encryption_key
        except IOError as e:
            error_log = ErrorLogEntry(
                error_id="archive_fail",
                severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
                component="Compliance Auditor",
                message="Failed to archive logs.",
                details=str(e),
                resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_TERMINATE
            )
            logger.error(f"{error_log.message}: {error_log.details}")
            raise ValueError(error_log.message)

    def restore_archived_logs(self, archive_name: str, encryption_key: bytes):
        """
        Restores logs from an encrypted archive for review or compliance checks.

        Args:
            archive_name (str): Name of the archive file to restore.
            encryption_key (bytes): Key to decrypt the archive.

        Returns:
            list: List of restored logs.
        """
        try:
            with open(archive_name, "rb") as archive_file:
                encrypted_data = archive_file.read()

            fernet = Fernet(encryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)

            with open("restored_audit.log", "wb") as restored_file:
                restored_file.write(decrypted_data)

            logger.info(f"Audit logs restored from archive {archive_name}")
            return json.loads(decrypted_data.decode())
        except Exception as e:
            error_log = ErrorLogEntry(
                error_id="restore_fail",
                severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
                component="Compliance Auditor",
                message="Failed to restore archived logs.",
                details=str(e),
                resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE
            )
            logger.error(f"{error_log.message}: {error_log.details}")
            raise ValueError(error_log.message)
