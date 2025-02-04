import uuid
import logging
from datetime import datetime, timezone
from google.protobuf.timestamp_pb2 import Timestamp

from src.logger.base_logger import base_logger
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertSeverity, AlertType
from src.crypto.constants import (
    ALERT_SEVERITY_INFO,
    ALERT_SEVERITY_WARNING,
    ALERT_SEVERITY_ERROR,
    ALERT_SEVERITY_CRITICAL,
    ALERT_SEVERITY_FATAL,
)

logger = logging.getLogger(__name__)


class SecureLogger:
    """
    Secure Logger for handling structured audit logging across critical paths.
    Uses Seigr's Alert protocol definitions for audit events.
    """

    SEIGR_ALERT_SEVERITIES = {
        AlertSeverity.ALERT_SEVERITY_INFO: logging.INFO,
        AlertSeverity.ALERT_SEVERITY_WARNING: logging.WARNING,
        AlertSeverity.ALERT_SEVERITY_ERROR: logging.ERROR,
        AlertSeverity.ALERT_SEVERITY_CRITICAL: logging.CRITICAL,
        AlertSeverity.ALERT_SEVERITY_FATAL: logging.CRITICAL,
    }

    def __init__(self):
        self.logger = base_logger
        logger.setLevel(logging.DEBUG)  # ✅ Enable Debug Logging for SecureLogger

    def log_audit_event(
        self, severity: int, category: str, message: str, sensitive: bool = False, **kwargs
    ):
        """
        Logs an audit event with structured metadata compliant with Seigr's Alert schema.
        """

        # ✅ Validate severity as an integer
        if not isinstance(severity, int) or severity not in self.SEIGR_ALERT_SEVERITIES:
            logger.error(f"❌ ERROR: Invalid severity level: {severity}")
            raise ValueError(f"Invalid severity level: {severity}")

        structured_severity = self.SEIGR_ALERT_SEVERITIES[severity]

        # ✅ Ensure timestamp is a `datetime` object
        timestamp_value = kwargs.pop("timestamp", datetime.now(timezone.utc))
        timestamp_proto = self._convert_to_protobuf_timestamp(timestamp_value)

        # ✅ Ensure category mapping for logging
        category_mapping = {
            "asymmetric_utils": "Cryptography",
            "cbor_utils": "CBOR Operations",
            "hashing": "Hashing",
            "integrity_verification": "Integrity Verification",
        }
        category = category_mapping.get(category, category)

        correlation_id = kwargs.get("correlation_id", str(uuid.uuid4()))
        sanitized_message = self._sanitize_message(message, sensitive)

        # ✅ Final log event
        self.logger.log_message(
            level=structured_severity,
            message=sanitized_message,
            category=category,
            sensitive=sensitive,
            correlation_id=correlation_id,
            timestamp=timestamp_proto,
            **kwargs,
        )

    @staticmethod
    def _convert_to_protobuf_timestamp(timestamp_value):
        """
        Converts a timestamp to a Protobuf Timestamp object.
        """
        if isinstance(timestamp_value, Timestamp):
            return timestamp_value

        if isinstance(timestamp_value, str):
            timestamp_value = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))

        if isinstance(timestamp_value, datetime):
            timestamp_proto = Timestamp()
            timestamp_proto.FromDatetime(timestamp_value)
            return timestamp_proto

        logger.error(
            f"❌ ERROR: Invalid timestamp type! Expected `datetime` or `Timestamp`, got `{type(timestamp_value).__name__}`"
        )
        raise TypeError(
            f"Timestamp must be `datetime` or `google.protobuf.timestamp_pb2.Timestamp`, got `{type(timestamp_value).__name__}`"
        )

    @staticmethod
    def _sanitize_message(message: str, sensitive: bool) -> str:
        """
        Sanitizes log messages by redacting sensitive information if flagged.
        """
        if not sensitive:
            return message
        sensitive_keywords = ["password", "secret", "token"]
        for keyword in sensitive_keywords:
            message = message.replace(keyword, "[REDACTED]")
        return message


# Singleton Instance
secure_logger = SecureLogger()
