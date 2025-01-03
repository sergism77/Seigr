# src/crypto/symmetric_utils.py

import logging
from datetime import datetime, timezone
from cryptography.fernet import Fernet, InvalidToken

from src.crypto.key_derivation import derive_key, generate_salt
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

# Logger Initialization
logger = logging.getLogger("symmetric_utils")
logging.basicConfig(
    filename="symmetric_operations.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

# Singleton SymmetricUtils Instance
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
    Encrypts data using SymmetricUtils.
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
    Decrypts data using SymmetricUtils.
    """
    _initialize_symmetric_utils(encryption_key, use_senary)
    return _symmetric_utils_instance.decrypt_data(encrypted_data, sensitive)


### 🛡️ SymmetricUtils Class ###

class SymmetricUtils:
    def __init__(self, encryption_key: bytes = None, use_senary: bool = False):
        """
        Initializes SymmetricUtils with encryption key and senary options.
        """
        self.encryption_key = encryption_key or self._generate_encryption_key()
        self.use_senary = use_senary
        logger.info(f"{SEIGR_CELL_ID_PREFIX} SymmetricUtils initialized.")

    ### 🔑 Encryption Key Management ###

    def _generate_encryption_key(self, password: str = None) -> bytes:
        """
        Generates a Fernet encryption key or derives it from a password.
        """
        if password:
            key = derive_key(password, generate_salt(), use_senary=False).encode()[:32]
            logger.info(f"{SEIGR_CELL_ID_PREFIX} Derived symmetric key from password.")
        else:
            key = Fernet.generate_key()
            logger.info(f"{SEIGR_CELL_ID_PREFIX} Generated new symmetric encryption key.")
        return key

    ### 🔒 Data Encryption ###

    def encrypt_data(self, data: bytes, sensitive: bool = False) -> bytes:
        """
        Encrypts data securely.
        """
        try:
            fernet = Fernet(self.encryption_key)
            encrypted_data = fernet.encrypt(data)
            self._log_encryption_event(data, sensitive)
            return encrypted_data
        except Exception as e:
            self._log_error(
                "encryption_fail",
                "Data encryption failed",
                str(e),
            )
            raise ValueError("Data encryption failed.") from e

    ### 🔓 Data Decryption ###

    def decrypt_data(self, encrypted_data: bytes, sensitive: bool = False) -> bytes:
        """
        Decrypts data securely.
        """
        try:
            fernet = Fernet(self.encryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)
            self._log_decryption_event(encrypted_data, sensitive)
            return decrypted_data
        except InvalidToken:
            self._log_error(
                "decryption_invalid_token",
                "Invalid decryption token provided.",
            )
            raise ValueError("Decryption failed: Invalid token")
        except Exception as e:
            self._log_error(
                "decryption_fail",
                "Data decryption failed",
                str(e),
            )
            raise ValueError("Data decryption failed.") from e

    ### 📝 Logging Events ###

    def _log_encryption_event(self, data: bytes, sensitive: bool):
        """
        Logs encryption events securely.
        """
        entry_id = f"{SEIGR_CELL_ID_PREFIX}_enc_{datetime.now(timezone.utc).isoformat()}"
        message = "Data encrypted securely." if not sensitive else "Sensitive data encrypted."

        logged_data = (
            encode_to_senary(data) if sensitive and self.use_senary else data[:10]
        )

        audit_entry = AuditLogEntry(
            log_id=entry_id,
            user_id="system",
            role="system",
            action=message,
            log_level=LogLevel.LOG_LEVEL_INFO,
            category=LogCategory.LOG_CATEGORY_SECURITY,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata={"senary_encoded": str(self.use_senary)},
        )
        logger.info(f"Encryption event: {audit_entry}")

    def _log_decryption_event(self, encrypted_data: bytes, sensitive: bool):
        """
        Logs decryption events securely.
        """
        entry_id = f"{SEIGR_CELL_ID_PREFIX}_dec_{datetime.now(timezone.utc).isoformat()}"
        message = "Data decrypted securely." if not sensitive else "Sensitive data decrypted."

        logged_data = (
            encode_to_senary(encrypted_data)
            if sensitive and self.use_senary
            else encrypted_data[:10]
        )

        audit_entry = AuditLogEntry(
            log_id=entry_id,
            user_id="system",
            role="system",
            action=message,
            log_level=LogLevel.LOG_LEVEL_INFO,
            category=LogCategory.LOG_CATEGORY_SECURITY,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata={"senary_encoded": str(self.use_senary)},
        )
        logger.info(f"Decryption event: {audit_entry}")

    def _log_error(self, error_id: str, message: str, details: str = ""):
        """
        Logs an error event securely.
        """
        error_entry = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_{error_id}",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="SymmetricUtils",
            message=message,
            details=details,
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE,
        )
        logger.error(f"Error: {error_entry}")
