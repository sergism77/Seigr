"""
📌 **Symmetric Encryption Utilities**
Handles **AES encryption, decryption, key derivation, structured logging, and cryptographic security**  
in compliance with **Seigr encryption protocols**.
"""

import logging
from datetime import datetime, timezone
from cryptography.fernet import Fernet, InvalidToken

# 🔐 Seigr Imports
from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.helpers import encode_to_senary
from src.crypto.key_derivation import derive_key, generate_salt, derive_key_from_password
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.audit_logging_pb2 import AuditLogEntry, LogCategory, LogLevel
from src.seigr_protocol.compiled.alerting_pb2 import (
    AlertSeverity,
)  # ✅ Using correct AlertSeverity from Seigr Protocol

logger = logging.getLogger(__name__)

# ===============================
# 🔑 **Symmetric Encryption Manager**
# ===============================


class SymmetricUtils:
    """
    **Handles AES-based encryption and decryption securely.**
    Supports **Fernet encryption, structured audit logging, and Senary encoding.**
    """

    def __init__(self, encryption_key: bytes = None, use_senary: bool = False):
        """
        **Initialize SymmetricUtils with a cryptographic key.**

        Args:
            encryption_key (bytes, optional): **Symmetric key for encryption/decryption.**
            use_senary (bool): **If True, encodes session tokens in Senary format.**
        """
        self.encryption_key = encryption_key or self._generate_encryption_key()
        self.use_senary = use_senary

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,  # ✅ Correct severity from Seigr Protocol
            category="Symmetric Encryption",
            message=f"{SEIGR_CELL_ID_PREFIX} SymmetricUtils initialized.",
        )

    # ===============================
    # 🛠 **Key Management**
    # ===============================

    def _generate_encryption_key(self, password: str = None) -> bytes:
        """
        **Generates an AES-compatible encryption key using PBKDF2.**
        """
        try:
            if password:
                salt = generate_salt()
                key = derive_key_from_password(password, salt, length=32)
            else:
                key = Fernet.generate_key()  # ✅ Ensures 32-byte key

            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Symmetric Encryption",
                message=f"{SEIGR_CELL_ID_PREFIX} ✅ Encryption key generated.",
            )
            return key
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_FATAL,
                category="Symmetric Encryption",
                message=f"{SEIGR_CELL_ID_PREFIX}_keygen_fail: Key generation failed. {str(e)}",
                sensitive=True,
            )
            raise ValueError("Encryption key generation failed.") from e
    
    # ===============================
    # 🔒 **Data Encryption**
    # ===============================

def encrypt_data(self, data: bytes, sensitive: bool = False) -> bytes:
    """
    **Encrypts data securely.**

    Args:
        data (bytes): **Data to encrypt.**
        sensitive (bool): **If True, logs encrypted data in Senary format.**

    Returns:
        bytes: **Encrypted ciphertext.**
    """
    try:
        if self.encryption_key is None:
            raise ValueError("Encryption key must be provided.")

        fernet = Fernet(self.encryption_key)
        encrypted_data = fernet.encrypt(data)

        # ✅ Log encryption event properly
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Encryption",
            message=f"{SEIGR_CELL_ID_PREFIX} 🔐 Data encrypted successfully.",
            log_data={"sensitive": sensitive}
        )

        return encrypted_data

    except Exception as e:
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,  # ✅ Ensure correct severity
            category="Encryption",
            message=f"{SEIGR_CELL_ID_PREFIX} ❌ Data encryption failed.",
            log_data={"error": str(e)},
            sensitive=True,
        )
        raise ValueError("Data encryption failed.") from e

    # ===============================
    # 🔓 **Data Decryption**
    # ===============================

    def decrypt_data(self, encrypted_data: bytes, sensitive: bool = False) -> bytes:
        """
        **Decrypts data securely.**

        Args:
            encrypted_data (bytes): **Ciphertext to decrypt.**
            sensitive (bool): **If True, logs decrypted data securely.**

        Returns:
            bytes: **Decrypted plaintext.**
        """
        try:
            fernet = Fernet(self.encryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)
            self._log_decryption_event(encrypted_data, sensitive)
            return decrypted_data
        except InvalidToken:
            secure_logger.log_audit_event(
                "decryption_invalid_token", "Invalid decryption token provided."
            )
            raise ValueError("Decryption failed: Invalid token")
        except Exception as e:
            secure_logger.log_audit_event("decryption_fail", "Data decryption failed", str(e))
            raise ValueError("Data decryption failed.") from e

    # ===============================
    # 📝 **Structured Logging**
    # ===============================

    def _log_encryption_event(self, data: bytes, sensitive: bool):
        """
        **Logs encryption events securely.**

        Args:
            data (bytes): **Data being encrypted.**
            sensitive (bool): **If True, logs encrypted data in Senary format.**
        """
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,  # ✅ Correct severity from Seigr Protocol
            category="Encryption",
            message=f"{SEIGR_CELL_ID_PREFIX} Encryption event logged",
        )

    def _log_decryption_event(self, encrypted_data: bytes, sensitive: bool):
        """
        **Logs decryption events securely.**

        Args:
            encrypted_data (bytes): **Encrypted data being decrypted.**
            sensitive (bool): **If True, logs decrypted data securely.**
        """
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,  # ✅ Correct severity from Seigr Protocol
            category="Decryption",
            message=f"{SEIGR_CELL_ID_PREFIX} Decryption event logged",
        )
