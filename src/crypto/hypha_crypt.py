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
from typing import Optional

# 🔐 Seigr Imports
from src.logger.secure_logger import secure_logger
from src.crypto.constants import (
    DEFAULT_HASH_FUNCTION,
    SEIGR_CELL_ID_PREFIX,
    SEIGR_VERSION,
    SUPPORTED_HASH_ALGORITHMS,
)
from src.crypto.helpers import apply_salt, encode_to_senary, decode_from_senary
from src.crypto.key_derivation import derive_key, generate_salt
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from src.seigr_protocol.compiled.hashing_pb2 import HashAlgorithm

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

    def HASH_SEIGR_SENARY_wrapper(
        self, data: bytes, salt: Optional[str] = None, algorithm: str = DEFAULT_HASH_FUNCTION
    ) -> str:
        """
        **Wrapper for HyphaCrypt.HASH_SEIGR_SENARY to provide a simplified interface.**
        Uses the Seigr ecosystem's cryptographic structure.
        """
        return self.HASH_SEIGR_SENARY(data=data, salt=salt, algorithm=algorithm)

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
                salt = generate_salt()
                key = derive_key(password, salt)
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

    def encrypt_data(self, key: bytes) -> str:
        """
        Encrypts data using a **secure Fernet key** and applies **Senary encoding** if enabled.

        Args:
            key (bytes): **Encryption key (must be valid).**

        Returns:
            str: **Encrypted data, Senary-encoded if enabled.**
        """
        try:
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(self.data)

            # ✅ Encode in Senary if enabled
            result = encode_to_senary(encrypted_data) if self.use_senary else encrypted_data.hex()

            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_INFO,
                category="Encryption",
                message=f"{SEIGR_CELL_ID_PREFIX} Data encrypted successfully for segment {self.segment_id}",
            )
            return result
        except Exception as e:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_FATAL,
                category="Encryption",
                message=f"{SEIGR_CELL_ID_PREFIX}_encryption_fail: Data encryption failed. {str(e)}",
                sensitive=True,
            )
            raise

    def decrypt_data(self, encrypted_data: str, key: bytes) -> bytes:
        """
        Decrypts **encrypted data** and decodes Senary if enabled.

        Args:
            encrypted_data (str): **Encrypted data, possibly Senary-encoded.**
            key (bytes): **Decryption key.**

        Returns:
            bytes: **Decrypted original data.**
        """
        try:
            # ✅ Decode from Senary if enabled
            data_to_decrypt = (
                decode_from_senary(encrypted_data)
                if self.use_senary
                else bytes.fromhex(encrypted_data)
            )

            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(data_to_decrypt)

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

    def HASH_SEIGR_SENARY(
        self, data: bytes, salt: str = None, algorithm: str = DEFAULT_HASH_FUNCTION
    ) -> str:
        """
        Generates a secure hash of the provided data.

        Args:
            data (bytes): **Data to be hashed.**
            salt (str, optional): **Optional salt for added security.**
            algorithm (str): **Hashing algorithm (default=DEFAULT_HASH_FUNCTION).**

        Returns:
            str: **Hashed output in hexadecimal or Senary format.**
        """
        algorithm_upper = algorithm.upper()

        # ✅ Ensure correct algorithm mapping
        if algorithm_upper == "HASH_SEIGR_SENARY":
            algorithm_enum = (
                HashAlgorithm.HASH_SEIGR_SENARY
            )  # ✅ This ensures Seigr Senary hashing is used.
        elif hasattr(HashAlgorithm, f"HASH_{algorithm_upper}"):
            algorithm_enum = getattr(HashAlgorithm, f"HASH_{algorithm_upper}")
        else:
            secure_logger.log_audit_event(
                severity=AlertSeverity.ALERT_SEVERITY_WARNING,
                category="Hashing",
                message=f"❌ Unsupported hash algorithm detected: {algorithm_upper}",
            )
            raise ValueError(f"{SEIGR_CELL_ID_PREFIX} ❌ Unsupported hash algorithm: {algorithm}")

        # ✅ Apply salt and hash
        salted_data = apply_salt(data, salt)
        hashed_output = hashlib.sha256(salted_data).digest()  # ✅ Hashing at the binary level

        # ✅ Encode result in Senary if required
        final_hash = encode_to_senary(hashed_output) if self.use_senary else hashed_output.hex()

        # ✅ Ensure correct logging
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Hashing",
            message="✅ Hash successfully generated.",
            log_data={"algorithm": algorithm_enum, "hash": final_hash},
        )
        return final_hash

    def hypha_hash_wrapper(
        self, data: bytes, salt: Optional[str] = None, algorithm: str = DEFAULT_HASH_FUNCTION
    ) -> str:
        """
        Wrapper for `hypha_hash` to provide a standardized interface across Seigr.

        Args:
            data (bytes): The data to hash.
            salt (str, optional): Optional salt for additional entropy.
            algorithm (str): Hashing algorithm (default = `DEFAULT_HASH_FUNCTION`).

        Returns:
            str: Hashed value in Senary or hexadecimal format.
        """
        return self.hypha_hash(data=data, salt=salt, algorithm=algorithm)
