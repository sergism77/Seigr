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
from src.crypto.key_derivation import derive_key, generate_salt
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
        **Generates a Fernet encryption key or derives it from a password.**

        Args:
            password (str, optional): **Password-based key derivation (PBKDF2).**

        Returns:
            bytes: **Generated encryption key.**
        """
        if password:
            key = derive_key(password, generate_salt(), use_senary=False).encode()[:32]
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Symmetric Encryption",
                message=f"{SEIGR_CELL_ID_PREFIX} Derived symmetric key from password.",
            )
        else:
            key = Fernet.generate_key()
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Symmetric Encryption",
                message=f"{SEIGR_CELL_ID_PREFIX} Generated new symmetric encryption key.",
            )
        return key

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
            fernet = Fernet(self.encryption_key)
            encrypted_data = fernet.encrypt(data)
            self._log_encryption_event(data, sensitive)
            return encrypted_data
        except Exception as e:
            secure_logger.log_audit_event("encryption_fail", "Data encryption failed", str(e))
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
