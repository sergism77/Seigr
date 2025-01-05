import logging
import sys
import uuid
from datetime import datetime, timezone

from src.logger.config import LOG_LEVEL, LOG_FORMAT
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertSeverity, AlertType

class BaseLogger:
    """
    A base logger for the Seigr ecosystem.
    Provides standardized logging across modules using Seigr Protocol definitions.
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
        Initializes the logger with standard configuration.
        """
        self.logger = logging.getLogger('SeigrLogger')
        self.logger.setLevel(LOG_LEVEL)

        if not self.logger.handlers:
            # Console Handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
            self.logger.addHandler(console_handler)

            # File Handler
            file_handler = logging.FileHandler('seigr_app.log')
            file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
            self.logger.addHandler(file_handler)

    def log_message(self, level: str, message: str, category: str = "", sensitive: bool = False):
        """
        Logs a message with the specified level and additional structured metadata.
        """
        if level.upper() not in self.SEVERITY_MAP:
            raise ValueError(f"Unsupported log level: {level}")

        severity = self.SEVERITY_MAP[level.upper()]
        log_entry = {
            'message': message,
            'category': category,
            'sensitive': sensitive,
            'severity': severity,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        # Create Alert message for structured logging
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            type=AlertType.ALERT_TYPE_SYSTEM,
            severity=severity,
            message=message,
            timestamp=log_entry['timestamp'],
            source_component=category or "general",
            metadata={"sensitive": str(sensitive)}
        )

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


# Singleton Instance
base_logger = BaseLogger()
