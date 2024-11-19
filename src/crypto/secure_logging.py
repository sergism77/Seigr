import logging
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from src.crypto.key_derivation import generate_salt, derive_key
from src.crypto.helpers import encode_to_senary, decode_from_senary
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

# Initialize logger
logger = logging.getLogger("secure_logger")
logging.basicConfig(
    filename="secure_audit.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

_secure_logger_instance = None


def _initialize_secure_logger():
    global _secure_logger_instance
    if _secure_logger_instance is None:
        _secure_logger_instance = SecureLogger()


def log_secure_action(
    action: str,
    metadata: dict = None,
    sensitive: bool = False,
    use_senary: bool = False,
):
    """Logs a secure action with optional metadata and sensitivity settings."""
    _initialize_secure_logger()
    severity = LogLevel.LOG_LEVEL_INFO if not sensitive else LogLevel.LOG_LEVEL_ALERT
    category = LogCategory.LOG_CATEGORY_SECURITY
    message = f"{action} with metadata: {metadata}" if metadata else action

    return _secure_logger_instance.log_audit_event(
        severity, category, message, sensitive=sensitive, use_senary=use_senary
    )


class SecureLogger:
    def __init__(self, encryption_key: bytes = None):
        self.encryption_key = encryption_key or self._generate_encryption_key()

    def _generate_encryption_key(self) -> bytes:
        key = Fernet.generate_key()
        logger.debug("Generated new encryption key for secure logging.")
        return key

    def encrypt_message(self, message: str, use_senary: bool = False) -> bytes:
        fernet = Fernet(self.encryption_key)
        encrypted_message = fernet.encrypt(message.encode())
        if use_senary:
            encrypted_message = encode_to_senary(encrypted_message)
            logger.debug("Message encrypted and senary-encoded.")
        else:
            logger.debug("Message encrypted.")
        return encrypted_message

    def decrypt_message(self, encrypted_message: bytes, is_senary: bool = False) -> str:
        try:
            if is_senary:
                encrypted_message = decode_from_senary(encrypted_message)
            fernet = Fernet(self.encryption_key)
            decrypted_message = fernet.decrypt(encrypted_message).decode()
            logger.debug("Message decrypted.")
            return decrypted_message
        except Exception as e:
            self._log_error("decryption_fail", "Decryption failed", e)
            raise ValueError("Decryption error in secure logging") from e

    def log_audit_event(
        self,
        severity: LogLevel,
        category: LogCategory,
        message: str,
        sensitive: bool = False,
        use_senary: bool = False,
    ) -> AuditLogEntry:
        try:
            entry_id = f"log_{datetime.now(timezone.utc).isoformat()}"
            if sensitive:
                message = self.encrypt_message(message, use_senary=use_senary)

            severity = self._validate_enum(severity, LogLevel, "LOG_LEVEL_INFO")
            category = self._validate_enum(
                category, LogCategory, "LOG_CATEGORY_GENERAL"
            )

            audit_entry = AuditLogEntry(
                log_id=entry_id,
                user_id="system_user",
                role="system",
                action=message,
                log_level=severity,
                category=category,
                timestamp=datetime.now(timezone.utc).isoformat(),
                metadata={"senary_encoded": str(use_senary)},
            )

            log_message = f"[{LogLevel.Name(audit_entry.log_level)}] {LogCategory.Name(audit_entry.category)}: {audit_entry.action}"
            logger.info(
                log_message
                + (
                    " (Encrypted and Senary Encoded)"
                    if use_senary and sensitive
                    else " (Encrypted)" if sensitive else ""
                )
            )
            return audit_entry
        except Exception as e:
            self._log_error("audit_logging_fail", "Failed to log audit event", e)
            raise ValueError("Audit event logging failed.") from e

    def _validate_enum(self, value, enum_type, default_name):
        try:
            # Check if the value is an integer that matches a value in the enum
            if not value in enum_type.values():
                default_value = getattr(enum_type, default_name)
                return default_value
            return value
        except Exception as e:
            raise ValueError(f"Failed to validate enum for {enum_type}.") from e

    def _log_error(self, error_id: str, message: str, exception: Exception):
        error_log = ErrorLogEntry(
            error_id=f"secure_logger_{error_id}",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Secure Logger",
            message=message,
            details=str(exception),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE,
        )
        logger.error(f"{message}: {exception}")
