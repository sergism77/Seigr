import logging
import sys
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from google.protobuf.timestamp_pb2 import Timestamp

from src.logger.config import LOG_LEVEL, LOG_FORMAT, LOG_FILE
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertSeverity, AlertType


class BaseLogger:
    """
    Enhanced base logger for the Seigr ecosystem.
    Provides standardized, structured logging compliant with Seigr Protocol definitions.
    Includes support for log rotation, sensitive data masking, and dynamic metadata.
    """

    _instance = None

    SEVERITY_MAP = {
        logging.DEBUG: AlertSeverity.ALERT_SEVERITY_INFO,
        logging.INFO: AlertSeverity.ALERT_SEVERITY_INFO,
        logging.WARNING: AlertSeverity.ALERT_SEVERITY_WARNING,
        logging.ERROR: AlertSeverity.ALERT_SEVERITY_ERROR,
        logging.CRITICAL: AlertSeverity.ALERT_SEVERITY_FATAL,
    }

    REVERSE_SEVERITY_MAP = {
        v: k for k, v in SEVERITY_MAP.items()
    }  # ✅ Reverse map for level retrieval

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(BaseLogger, cls).__new__(cls)
            cls._instance._initialize_logger()
        return cls._instance

    def _initialize_logger(self):
        """
        Initializes the logger with standard configuration, including rotation handlers.
        """
        self.logger = logging.getLogger("SeigrLogger")
        self.logger.setLevel(LOG_LEVEL)

        if not self.logger.handlers:
            # Console Handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
            self.logger.addHandler(console_handler)

            # Rotating File Handler
            rotating_file_handler = RotatingFileHandler(
                LOG_FILE, maxBytes=5 * 10**6, backupCount=5  # 5 MB file size, 5 backups
            )
            rotating_file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
            self.logger.addHandler(rotating_file_handler)

    def log_message(
        self, level, message: str, category: str = "general", sensitive: bool = False, **kwargs
    ):
        """
        Logs a structured message with the specified level and additional metadata.
        Ensures timestamps remain in the correct format.
        """

        # ✅ Ensure level is mapped correctly
        if isinstance(level, str):
            level = level.upper()
            level = getattr(logging, level, None)

        if level not in self.SEVERITY_MAP:
            raise ValueError(f"Unsupported log level: {level}")

        severity = self.SEVERITY_MAP[level]
        correlation_id = kwargs.get("correlation_id", str(uuid.uuid4()))

        # ✅ Get timestamp from kwargs or use current UTC time
        timestamp_value = kwargs.get("timestamp", datetime.now(timezone.utc))

        # 🔍 Debug log to track timestamp format
        self.logger.debug(
            f"🟣 DEBUG: base_logger received timestamp -> {timestamp_value} (type: {type(timestamp_value).__name__})"
        )

        # ✅ Ensure timestamp is a Protobuf `Timestamp`
        if isinstance(timestamp_value, str):
            self.logger.warning(
                f"⚠️ WARNING: base_logger received timestamp as a string! Converting..."
            )
            timestamp_value = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))

        if isinstance(timestamp_value, datetime):
            timestamp_proto = Timestamp()
            timestamp_proto.FromDatetime(timestamp_value)
        elif isinstance(timestamp_value, Timestamp):
            timestamp_proto = timestamp_value
        else:
            self.logger.error(
                f"❌ ERROR: Invalid timestamp type! Expected `datetime` or `Timestamp`, got `{type(timestamp_value).__name__}`"
            )
            raise TypeError(
                f"Timestamp must be `datetime` or `google.protobuf.timestamp_pb2.Timestamp`, got `{type(timestamp_value).__name__}`"
            )

        # ✅ Final debug log before structuring the alert
        self.logger.debug(
            f"✅ DEBUG: Using timestamp {timestamp_proto.ToJsonString()} (type: {type(timestamp_proto)})"
        )

        # ✅ Create Alert message
        alert = Alert(
            alert_id=correlation_id,
            type=AlertType.ALERT_TYPE_SYSTEM,
            severity=severity,
            message=self._redact_sensitive_data(message) if sensitive else message,
            timestamp=timestamp_proto,  # ✅ Always Protobuf Timestamp
            source_component=category,
            metadata={"sensitive": str(sensitive), **{k: str(v) for k, v in kwargs.items()}},
        )

        # ✅ Map severity to correct logging level
        log_method = self.logger.log
        log_method(self.REVERSE_SEVERITY_MAP[severity], alert)

    def _redact_sensitive_data(self, message: str) -> str:
        """
        Redacts sensitive information in log messages.

        Args:
            message (str): The log message.

        Returns:
            str: The redacted log message.
        """
        sensitive_keywords = ["password", "secret", "token"]
        for keyword in sensitive_keywords:
            message = message.replace(keyword, "[REDACTED]")
        return message


# Singleton Instance
base_logger = BaseLogger()
