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

    def log_audit_event(self, severity: int, category: str, message: str, sensitive: bool = False, **kwargs):
        """
        Logs an audit event with structured metadata compliant with Seigr's Alert schema.

        Args:
            severity (int): AlertSeverity level.
            category (str): Audit category (e.g., Encode, Decode, FileIO).
            message (str): Audit log message.
            sensitive (bool): Flag indicating if sensitive data is involved.
            kwargs: Additional metadata fields to include.
        """
        if severity not in AlertSeverity.values():
            raise ValueError(f"Invalid severity level: {severity}")

        timestamp = datetime.now(timezone.utc).isoformat()
        correlation_id = kwargs.get("correlation_id", str(uuid.uuid4()))
        sanitized_message = self._sanitize_message(message, sensitive)

        # Create Alert message for structured logging
        alert = Alert(
            alert_id=correlation_id,
            type=AlertType.ALERT_TYPE_SYSTEM,
            severity=severity,
            message=sanitized_message,
            timestamp=timestamp,
            source_component=category,
            metadata={
                "sensitive": str(sensitive),
                **{k: str(v) for k, v in kwargs.items()}
            }
        )

        # Map severity to logger levels and log the structured message
        log_level = self._severity_to_level(severity)
        self.logger.log_message(
            level=log_level,
            message=sanitized_message,
            category=category,
            sensitive=sensitive,
            **kwargs
        )

    @staticmethod
    def _sanitize_message(message: str, sensitive: bool) -> str:
        """
        Sanitizes log messages by redacting sensitive information if flagged.

        Args:
            message (str): The log message.
            sensitive (bool): Whether the message contains sensitive information.

        Returns:
            str: The sanitized log message.
        """
        if not sensitive:
            return message
        # Redact known sensitive keywords
        sensitive_keywords = ["password", "secret", "token"]
        for keyword in sensitive_keywords:
            message = message.replace(keyword, "[REDACTED]")
        return message

    @staticmethod
    def _severity_to_level(severity: int) -> str:
        """
        Maps AlertSeverity to logging level.

        Args:
            severity (int): AlertSeverity value.

        Returns:
            str: Corresponding log level ('DEBUG', 'INFO', etc.).
        """
        severity_map = {
            AlertSeverity.ALERT_SEVERITY_INFO: "INFO",
            AlertSeverity.ALERT_SEVERITY_WARNING: "WARNING",
            AlertSeverity.ALERT_SEVERITY_CRITICAL: "CRITICAL",
            AlertSeverity.ALERT_SEVERITY_FATAL: "ERROR",
        }
        return severity_map.get(severity, "DEBUG")


# Singleton Instance
secure_logger = SecureLogger()
