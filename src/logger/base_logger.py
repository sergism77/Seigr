import logging
import sys
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
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
        'DEBUG': AlertSeverity.ALERT_SEVERITY_INFO,
        'INFO': AlertSeverity.ALERT_SEVERITY_INFO,
        'WARNING': AlertSeverity.ALERT_SEVERITY_WARNING,
        'ERROR': AlertSeverity.ALERT_SEVERITY_CRITICAL,
        'CRITICAL': AlertSeverity.ALERT_SEVERITY_FATAL,
    }

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(BaseLogger, cls).__new__(cls)
            cls._instance._initialize_logger()
        return cls._instance

    def _initialize_logger(self):
        """
        Initializes the logger with standard configuration, including rotation handlers.
        """
        self.logger = logging.getLogger('SeigrLogger')
        self.logger.setLevel(LOG_LEVEL)

        if not self.logger.handlers:
            # Console Handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
            self.logger.addHandler(console_handler)

            # Rotating File Handler
            rotating_file_handler = RotatingFileHandler(
                LOG_FILE, maxBytes=10**6, backupCount=3  # 1 MB file size, 3 backups
            )
            rotating_file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
            self.logger.addHandler(rotating_file_handler)

    def log_message(self, level: str, message: str, category: str = "", sensitive: bool = False, **kwargs):
        """
        Logs a message with the specified level and additional structured metadata.

        Args:
            level (str): Log level ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL').
            message (str): Message to log.
            category (str): Log category (e.g., module or function name).
            sensitive (bool): Indicates whether the message contains sensitive information.
            kwargs: Additional metadata to include in the structured log.
        """
        if level.upper() not in self.SEVERITY_MAP:
            raise ValueError(f"Unsupported log level: {level}")

        severity = self.SEVERITY_MAP[level.upper()]
        timestamp = datetime.now(timezone.utc).isoformat()
        correlation_id = kwargs.get('correlation_id', str(uuid.uuid4()))

        log_entry = {
            'message': self._redact_sensitive_data(message) if sensitive else message,
            'category': category,
            'sensitive': sensitive,
            'severity': severity,
            'timestamp': timestamp,
            'correlation_id': correlation_id,
            **kwargs,
        }

        # Create Alert message for structured logging
        alert = Alert(
            alert_id=correlation_id,
            type=AlertType.ALERT_TYPE_SYSTEM,
            severity=severity,
            message=log_entry['message'],
            timestamp=timestamp,
            source_component=category or "general",
            metadata={k: str(v) for k, v in log_entry.items() if k != 'message'}
        )

        # Log based on severity
        if level.upper() == 'DEBUG':
            self.logger.debug(alert)
        elif level.upper() == 'INFO':
            self.logger.info(alert)
        elif level.upper() == 'WARNING':
            self.logger.warning(alert)
        elif level.upper() == 'ERROR':
            self.logger.error(alert)
        elif level.upper() == 'CRITICAL':
            self.logger.critical(alert)

    def _redact_sensitive_data(self, message: str) -> str:
        """
        Redacts sensitive information in log messages.

        Args:
            message (str): The log message.

        Returns:
            str: The redacted log message.
        """
        # Example logic: replace sensitive keywords (can be extended as needed)
        sensitive_keywords = ['password', 'secret', 'token']
        for keyword in sensitive_keywords:
            message = message.replace(keyword, '[REDACTED]')
        return message


# Singleton Instance
base_logger = BaseLogger()
