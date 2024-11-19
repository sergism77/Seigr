import logging
from datetime import datetime, timezone
from cryptography.fernet import Fernet, InvalidToken
from src.crypto.key_derivation import derive_key, generate_salt
from src.crypto.helpers import encode_to_senary
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

# Initialize the logger for symmetric operations
logger = logging.getLogger(__name__)

# Singleton instance of SymmetricUtils for top-level functions
_symmetric_utils_instance = None


def _initialize_symmetric_utils(encryption_key=None, use_senary=False):
    global _symmetric_utils_instance
    if _symmetric_utils_instance is None:
        _symmetric_utils_instance = SymmetricUtils(
            encryption_key=encryption_key, use_senary=use_senary
        )


def encrypt_data(
    data: bytes, encryption_key=None, sensitive: bool = False, use_senary: bool = False
) -> bytes:
    """
    Top-level function to encrypt data using SymmetricUtils.
    """
    _initialize_symmetric_utils(encryption_key, use_senary)
    return _symmetric_utils_instance.encrypt_data(data, sensitive)


def decrypt_data(
    encrypted_data: bytes,
    encryption_key=None,
    sensitive: bool = False,
    use_senary: bool = False,
) -> bytes:
    """
    Top-level function to decrypt data using SymmetricUtils.
    """
    _initialize_symmetric_utils(encryption_key, use_senary)
    return _symmetric_utils_instance.decrypt_data(encrypted_data, sensitive)


class SymmetricUtils:
    def __init__(self, encryption_key: bytes = None, use_senary: bool = False):
        """
        Initializes SymmetricUtils with an optional encryption key and senary encoding.

        Args:
            encryption_key (bytes): Predefined encryption key; if not provided, generates a new one.
            use_senary (bool): If True, logs and operations involving sensitive data are senary-encoded.
        """
        self.encryption_key = encryption_key or self._generate_encryption_key()
        self.use_senary = use_senary

    def _generate_encryption_key(self, password: str = None) -> bytes:
        """Generates a new Fernet encryption key, optionally derived from a password."""
        if password:
            key = derive_key(password, generate_salt(), use_senary=False).encode()[:32]
            logger.info("Derived encryption key from password.")
        else:
            key = Fernet.generate_key()
            logger.info("Generated new symmetric encryption key.")
        return key

    def encrypt_data(self, data: bytes, sensitive: bool = False) -> bytes:
        """
        Encrypts data using the Fernet symmetric encryption algorithm.

        Args:
            data (bytes): The data to be encrypted.
            sensitive (bool): Indicates if the data is sensitive and should be logged securely.

        Returns:
            bytes: The encrypted data.
        """
        try:
            fernet = Fernet(self.encryption_key)
            encrypted_data = fernet.encrypt(data)
            self._log_encryption_event(data, sensitive)
            return encrypted_data
        except Exception as e:
            self._log_error("encryption_error", "Data encryption failed", str(e))
            raise ValueError("Failed to encrypt data")

    def decrypt_data(self, encrypted_data: bytes, sensitive: bool = False) -> bytes:
        """
        Decrypts data using the Fernet symmetric encryption algorithm.

        Args:
            encrypted_data (bytes): The encrypted data to be decrypted.
            sensitive (bool): Indicates if the data is sensitive and should be logged securely.

        Returns:
            bytes: The decrypted data.
        """
        try:
            fernet = Fernet(self.encryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)
            self._log_decryption_event(encrypted_data, sensitive)
            return decrypted_data
        except InvalidToken:
            self._log_error("decryption_error", "Invalid decryption token provided")
            raise ValueError("Decryption failed: Invalid token")
        except Exception as e:
            self._log_error("decryption_error", "Data decryption failed", str(e))
            raise ValueError("Failed to decrypt data")

    def _log_encryption_event(self, data: bytes, sensitive: bool):
        """
        Logs an encryption event with optional sensitivity handling.

        Args:
            data (bytes): Data being encrypted (logged only if not sensitive).
            sensitive (bool): Flag indicating if data is sensitive.
        """
        entry_id = f"enc_{datetime.now(timezone.utc).isoformat()}"
        message = "Data encrypted" if not sensitive else "Sensitive data encrypted"

        # Senary encoding for sensitive data
        logged_data = (
            encode_to_senary(data) if sensitive and self.use_senary else data[:10]
        )

        audit_entry = AuditLogEntry(
            log_id=entry_id,
            user_id="unknown_user",
            role="unknown_role",
            action=message,
            log_level=LogLevel.LOG_LEVEL_INFO,
            category=LogCategory.LOG_CATEGORY_SECURITY,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata={"senary_encoded": str(self.use_senary)},
        )
        logger.info(f"Encryption event: {audit_entry}")

    def _log_decryption_event(self, encrypted_data: bytes, sensitive: bool):
        """
        Logs a decryption event with optional sensitivity handling.

        Args:
            encrypted_data (bytes): Encrypted data being decrypted (logged only if not sensitive).
            sensitive (bool): Flag indicating if data is sensitive.
        """
        entry_id = f"dec_{datetime.now(timezone.utc).isoformat()}"
        message = "Data decrypted" if not sensitive else "Sensitive data decrypted"

        # Optional senary encoding for sensitive data
        logged_data = (
            encode_to_senary(encrypted_data)
            if sensitive and self.use_senary
            else encrypted_data[:10]
        )

        audit_entry = AuditLogEntry(
            log_id=entry_id,
            user_id="unknown_user",
            role="unknown_role",
            action=message,
            log_level=LogLevel.LOG_LEVEL_INFO,
            category=LogCategory.LOG_CATEGORY_SECURITY,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata={"senary_encoded": str(self.use_senary)},
        )
        logger.info(f"Decryption event: {audit_entry}")

    def _log_error(self, error_id: str, message: str, details: str = ""):
        """
        Logs an error event related to symmetric encryption.

        Args:
            error_id (str): Unique identifier for the error.
            message (str): Descriptive error message.
            details (str): Additional details about the error.
        """
        error_entry = ErrorLogEntry(
            error_id=error_id,
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="SymmetricUtils",
            message=message,
            details=details,
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE,
        )
        logger.error(f"Error event: {error_entry}")
