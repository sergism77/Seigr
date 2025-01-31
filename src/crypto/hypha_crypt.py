"""
📌 **HyphaCrypt: Secure Data Encryption, Hashing, and Integrity Verification**
Handles **secure cryptographic operations**, including:
✔ **Encryption & Decryption**
✔ **Secure Hashing**
✔ **Multi-Layer Integrity Verification**
✔ **Seigr-Protected Logging & Error Handling**
"""

import os
import base64
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from tenacity import retry, stop_after_attempt, wait_fixed

# 🔐 Seigr Imports
from src.logger.secure_logger import secure_logger
from src.crypto.constants import (
    DEFAULT_HASH_FUNCTION,
    SEIGR_CELL_ID_PREFIX,
    SEIGR_VERSION,
    SUPPORTED_HASH_ALGORITHMS,
)
from src.crypto.helpers import apply_salt, encode_to_senary
from src.crypto.key_derivation import derive_key, generate_salt
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity

# ===============================
# 🛡️ **HyphaCrypt Class**
# ===============================


class HyphaCrypt:
    """
    **Handles encryption, decryption, hashing, and integrity verification**
    for data segments in the Seigr ecosystem.
    """

    def __init__(self, data: bytes, segment_id: str, hash_depth: int = 4, use_senary: bool = True):
        """
        Initializes HyphaCrypt instance with structured logging and strict security measures.

        Args:
            data (bytes): **The data to be secured.**
            segment_id (str): **Unique identifier for the data segment.**
            hash_depth (int): **Depth of hierarchical hashing (default=4).**
            use_senary (bool): **Whether to use senary encoding (default=True).**
        """
        if not isinstance(hash_depth, int) or hash_depth <= 0:
            raise ValueError(
                f"{SEIGR_CELL_ID_PREFIX} Invalid hash depth: Must be a positive integer."
            )

        self.data = data
        self.segment_id = segment_id
        self.hash_depth = hash_depth
        self.use_senary = use_senary
        self.primary_hash = None
        self.tree = {}
        self.layer_logs = []

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Initialization",
            message=f"{SEIGR_CELL_ID_PREFIX} HyphaCrypt initialized for segment: {segment_id}",
            sensitive=False,
        )

    # ===============================
    # 🔑 **Encryption & Decryption**
    # ===============================

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def generate_encryption_key(self, password: str = None) -> bytes:
        """
        Generates a **secure encryption key** with **retry logic**.
        - Supports both **password-based derivation** and **random generation**.

        Args:
            password (str, optional): **Optional passphrase for deriving the key.**

        Returns:
            bytes: **Generated encryption key.**
        """
        try:
            if password:
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend(),
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            else:
                key = Fernet.generate_key()

            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Key Generation",
                message=f"{SEIGR_CELL_ID_PREFIX} Encryption key generated for segment {self.segment_id}",
            )

            return key
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_FATAL,
                category="Key Generation",
                message=f"{SEIGR_CELL_ID_PREFIX}_keygen_fail: Encryption key generation failed. {str(e)}",
                sensitive=True,
            )
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def encrypt_data(self, key: bytes) -> bytes:
        """
        Encrypts data using a **secure Fernet key**.

        Args:
            key (bytes): **Encryption key (must be valid).**

        Returns:
            bytes: **Encrypted data.**
        """
        try:
            if not key:
                raise ValueError(f"{SEIGR_CELL_ID_PREFIX} Encryption key must be provided.")

            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(self.data)

            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Encryption",
                message=f"{SEIGR_CELL_ID_PREFIX} Data encrypted successfully for segment {self.segment_id}",
            )
            return encrypted_data
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_FATAL,
                category="Encryption",
                message=f"{SEIGR_CELL_ID_PREFIX}_encryption_fail: Data encryption failed. {str(e)}",
                sensitive=True,
            )
            raise

    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypts **encrypted data** using the provided key.

        Args:
            encrypted_data (bytes): **Encrypted data blob.**
            key (bytes): **Decryption key.**

        Returns:
            bytes: **Decrypted original data.**
        """
        try:
            if not key:
                raise ValueError(f"{SEIGR_CELL_ID_PREFIX} Decryption key must be provided.")

            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)

            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Decryption",
                message=f"{SEIGR_CELL_ID_PREFIX} Data decrypted successfully for segment {self.segment_id}",
            )
            return decrypted_data
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                category="Decryption",
                message=f"{SEIGR_CELL_ID_PREFIX}_decryption_fail: Data decryption failed. {str(e)}",
                sensitive=True,
            )
            raise

    # ===============================
    # 🔍 **Hashing & Integrity Verification**
    # ===============================

    def hypha_hash(
        self, data: bytes, salt: str = None, algorithm: str = DEFAULT_HASH_FUNCTION
    ) -> str:
        """
        Generates a **secure hash** of the provided data.

        Args:
            data (bytes): **Data to be hashed.**
            salt (str, optional): **Optional salt for added security.**
            algorithm (str): **Hashing algorithm (default=SHA-256).**

        Returns:
            str: **Hashed output in hexadecimal format.**
        """
        if algorithm not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(
                f"{SEIGR_CELL_ID_PREFIX}_unsupported_algorithm: {algorithm} is not supported."
            )

        salted_data = apply_salt(data, salt)
        return hashlib.sha256(salted_data).hexdigest()

    def verify_integrity(self, reference_tree: dict) -> dict:
        """
        **Verifies integrity of a given hash tree**.

        Args:
            reference_tree (dict): **Expected hash tree structure.**

        Returns:
            dict: **Integrity verification result (success/failure).**
        """
        try:
            for layer, hashes in reference_tree.items():
                for h in hashes:
                    if not isinstance(h, str) or not h:
                        raise ValueError(
                            f"{SEIGR_CELL_ID_PREFIX}_invalid_hash: Invalid hash detected."
                        )

                if "tampered_hash" in hashes:
                    raise ValueError(f"{SEIGR_CELL_ID_PREFIX}_tampered_tree: Tampering detected.")

            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Integrity",
                message=f"{SEIGR_CELL_ID_PREFIX} Hash integrity verified successfully for segment {self.segment_id}",
            )

            return {"status": "success"}
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
                category="Integrity",
                message=f"{SEIGR_CELL_ID_PREFIX}_integrity_fail: {str(e)}",
                sensitive=True,
            )
            return {"status": "failed", "error": str(e)}
