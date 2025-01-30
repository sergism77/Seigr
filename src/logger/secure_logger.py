import uuid
import logging
from datetime import datetime, timezone

from google.protobuf.timestamp_pb2 import Timestamp

from src.logger.base_logger import base_logger
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertSeverity, AlertType

logger = logging.getLogger(__name__)


class SecureLogger:
    """
    Secure Logger for handling structured audit logging across critical paths.
    Uses Seigr's Alert protocol definitions for audit events.
    """

    def __init__(self):
        self.logger = base_logger
        logger.setLevel(logging.DEBUG)  # ✅ Enable Debug Logging for SecureLogger

    def log_audit_event(
        self, severity: int, category: str, message: str, sensitive: bool = False, **kwargs
    ):
        """
        Logs an audit event with structured metadata compliant with Seigr's Alert schema.
        """
        if severity not in AlertSeverity.values():
            raise ValueError(f"Invalid severity level: {severity}")

        timestamp_proto = Timestamp()
        timestamp_value = kwargs.get("timestamp", datetime.now(timezone.utc))

        logger.debug(
            f"🔍 Debug: Received timestamp for logging: {timestamp_value} (type: {type(timestamp_value).__name__})"
        )

        if not isinstance(timestamp_value, datetime):
            logger.error(
                f"❌ ERROR: `timestamp_value` is not datetime: {timestamp_value} | Type: {type(timestamp_value).__name__}"
            )
            raise TypeError(
                f"`timestamp_value` must be `datetime`, got `{type(timestamp_value).__name__}`"
            )

        timestamp_proto.FromDatetime(timestamp_value)

        logger.debug(
            f"✅ Debug: Converted to Protobuf Timestamp -> {timestamp_proto.ToJsonString()} (type: {type(timestamp_proto)})"
        )

        correlation_id = kwargs.get("correlation_id", str(uuid.uuid4()))
        sanitized_message = self._sanitize_message(message, sensitive)

        # ✅ Log before passing to base_logger.log_message
        logger.debug(
            f"🟢 DEBUG: Passing to base_logger.log_message() -> timestamp: {timestamp_proto} (type: {type(timestamp_proto)})"
        )

        self.logger.log_message(
            level=self._severity_to_level(severity),
            message=sanitized_message,
            category=category,
            sensitive=sensitive,
            correlation_id=correlation_id,
            timestamp=timestamp_proto,  # ✅ Ensure this remains a `Timestamp`
            **kwargs,
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
