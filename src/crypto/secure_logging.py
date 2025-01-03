# src/crypto/secure_logging.py

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
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertType, AlertSeverity
from src.crypto.constants import SEIGR_CELL_ID_PREFIX

# Initialize Logger
logger = logging.getLogger("secure_logger")
logging.basicConfig(
    filename="secure_audit.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

# Singleton Secure Logger Instance
_secure_logger_instance = None


def _initialize_secure_logger():
    """Initialize a singleton instance of SecureLogger."""
    global _secure_logger_instance
    if _secure_logger_instance is None:
        _secure_logger_instance = SecureLogger()


def log_secure_action(
    action: str,
    metadata: dict = None,
    sensitive: bool = False,
    use_senary: bool = False,
):
    """
    Logs a secure action with optional metadata and sensitivity settings.

    Args:
        action (str): Action description.
        metadata (dict): Optional metadata for additional context.
        sensitive (bool): Flag for sensitive actions.
        use_senary (bool): Whether to apply senary encoding.
    """
    _initialize_secure_logger()
    severity = LogLevel.LOG_LEVEL_INFO if not sensitive else LogLevel.LOG_LEVEL_ALERT
    category = LogCategory.LOG_CATEGORY_SECURITY
    message = f"{action} | Metadata: {metadata}" if metadata else action

    return _secure_logger_instance.log_audit_event(
        severity, category, message, sensitive=sensitive, use_senary=use_senary
    )


### 🛡️ SecureLogger Class ###

class SecureLogger:
    def __init__(self, encryption_key: bytes = None):
        self.encryption_key = encryption_key or self._generate_encryption_key()
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} SecureLogger initialized with encryption key.")

    ### 🔑 Key Generation ###

    def _generate_encryption_key(self) -> bytes:
        """Generates a secure encryption key for secure logging."""
        key = Fernet.generate_key()
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} Generated encryption key for secure logging.")
        return key

    ### 🔒 Encryption & Decryption ###

    def encrypt_message(self, message: str, use_senary: bool = False) -> str:
        """
        Encrypts a message, optionally encoding it in senary.

        Args:
            message (str): Message to encrypt.
            use_senary (bool): Whether to encode in senary format.

        Returns:
            str: Encrypted (and optionally senary-encoded) message.
        """
        try:
            fernet = Fernet(self.encryption_key)
            encrypted_message = fernet.encrypt(message.encode())
            if use_senary:
                encrypted_message = encode_to_senary(encrypted_message)
                logger.debug("Message encrypted and senary-encoded.")
            else:
                logger.debug("Message encrypted.")
            return encrypted_message
        except Exception as e:
            self._log_error("encryption_fail", "Encryption failed", e)
            raise ValueError("Encryption error in secure logging") from e

    def decrypt_message(self, encrypted_message: str, is_senary: bool = False) -> str:
        """
        Decrypts an encrypted message, optionally decoding from senary.

        Args:
            encrypted_message (str): Encrypted message.
            is_senary (bool): Whether the message is senary-encoded.

        Returns:
            str: Decrypted message.
        """
        try:
            if is_senary:
                encrypted_message = decode_from_senary(encrypted_message)
            fernet = Fernet(self.encryption_key)
            decrypted_message = fernet.decrypt(encrypted_message).decode()
            logger.debug("Message decrypted successfully.")
            return decrypted_message
        except Exception as e:
            self._log_error("decryption_fail", "Decryption failed", e)
            raise ValueError("Decryption error in secure logging") from e

    ### 📊 Audit Logging ###

    def log_audit_event(
        self,
        severity: LogLevel,
        category: LogCategory,
        message: str,
        sensitive: bool = False,
        use_senary: bool = False,
    ) -> AuditLogEntry:
        """
        Logs an audit event securely with optional encryption and senary encoding.

        Args:
            severity (LogLevel): Log severity level.
            category (LogCategory): Log category.
            message (str): Log message.
            sensitive (bool): Flag for sensitive events.
            use_senary (bool): Whether to apply senary encoding.

        Returns:
            AuditLogEntry: Structured audit log entry.
        """
        try:
            entry_id = f"log_{datetime.now(timezone.utc).isoformat()}"
            if sensitive:
                message = self.encrypt_message(message, use_senary=use_senary)

            severity = self._validate_enum(severity, LogLevel, "LOG_LEVEL_INFO")
            category = self._validate_enum(category, LogCategory, "LOG_CATEGORY_GENERAL")

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
            logger.info(log_message)
            return audit_entry
        except Exception as e:
            self._log_error("audit_logging_fail", "Failed to log audit event", e)
            raise ValueError("Audit event logging failed.") from e

    ### 🛡️ Enum Validation ###

    def _validate_enum(self, value, enum_type, default_name):
        if value not in enum_type.values():
            return getattr(enum_type, default_name)
        return value

    ### ⚠️ Error Logging ###

    def _log_error(self, error_id: str, message: str, exception: Exception):
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_{error_id}",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Secure Logger",
            message=message,
            details=str(exception),
        )
        logger.error(f"{message}: {exception}")
