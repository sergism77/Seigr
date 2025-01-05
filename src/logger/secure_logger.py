import uuid
from datetime import datetime, timezone

from src.logger.base_logger import base_logger
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertSeverity, AlertType


class SecureLogger:
    """
    Secure Logger for handling structured audit logging across critical paths.
    Uses Seigr's Alert protocol definitions for audit events.
    """
    def __init__(self):
        self.logger = base_logger

    def log_audit_event(self, severity: int, category: str, message: str, sensitive: bool = False, use_senary: bool = False):
        """
        Logs an audit event with structured metadata compliant with Seigr's Alert schema.

        Args:
            severity (int): AlertSeverity level.
            category (str): Audit category (e.g., Encode, Decode, FileIO).
            message (str): Audit log message.
            sensitive (bool): Flag indicating if sensitive data is involved.
            use_senary (bool): Flag indicating if senary encoding is used.
        """
        if severity not in AlertSeverity.values():
            raise ValueError(f"Invalid severity level: {severity}")

        alert = Alert(
            alert_id=str(uuid.uuid4()),
            type=AlertType.ALERT_TYPE_SYSTEM,
            severity=severity,  # Pass integer directly
            message=message,
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_component=category,
            metadata={
                "sensitive": str(sensitive),
                "use_senary": str(use_senary)
            }
        )

        # Map severity levels to logging methods
        if severity == AlertSeverity.ALERT_SEVERITY_INFO:
            self.logger.log_message(
                level='INFO',
                message=message,
                category=category,
                sensitive=sensitive
            )
        elif severity == AlertSeverity.ALERT_SEVERITY_WARNING:
            self.logger.log_message(
                level='WARNING',
                message=message,
                category=category,
                sensitive=sensitive
            )
        elif severity == AlertSeverity.ALERT_SEVERITY_CRITICAL:
            self.logger.log_message(
                level='CRITICAL',
                message=message,
                category=category,
                sensitive=sensitive
            )
        elif severity == AlertSeverity.ALERT_SEVERITY_FATAL:
            self.logger.log_message(
                level='ERROR',
                message=message,
                category=category,
                sensitive=sensitive
            )
        else:
            self.logger.log_message(
                level='DEBUG',
                message=message,
                category=category,
                sensitive=sensitive
            )


# Singleton Instance
secure_logger = SecureLogger()
