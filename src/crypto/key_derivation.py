"""
📌 **Key Derivation Module**
Handles **secure cryptographic key derivation**, **HMAC verification**, and **structured key storage**
in full compliance with **Seigr security protocols**.
"""

import os
import hashlib
import logging

# 🔐 Seigr Imports
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from src.crypto.constants import SALT_SIZE, SEIGR_CELL_ID_PREFIX
from src.crypto.helpers import encode_to_senary
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity  # ✅ Correct Enum Import

logger = logging.getLogger(__name__)

# ===============================
# 🔑 **Key Derivation Utilities**
# ===============================


def generate_salt(length: int = SALT_SIZE) -> bytes:
    """
    **Generates a cryptographic salt.**

    Args:
        length (int): **Length of the salt in bytes.**

    Returns:
        bytes: **Generated salt.**
    """
    try:
        salt = os.urandom(length)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Key Management",
            message=f"{SEIGR_CELL_ID_PREFIX} Successfully generated cryptographic salt.",
        )
        return salt
    except Exception as e:
        secure_logger.log_audit_event("salt_generation_fail", "Salt generation failed", e)
        raise ValueError("Salt generation failed.") from e


def derive_key_from_password(
    password: str, salt: bytes = None, length: int = 32, iterations: int = 100000
) -> bytes:
    """
    **Derives a cryptographic key from a password using PBKDF2-HMAC-SHA256.**

    Args:
        password (str): **Password for key derivation.**
        salt (bytes): **Salt for PBKDF2. Generates a new one if None.**
        length (int): **Length of the derived key.**
        iterations (int): **Number of iterations for PBKDF2.**

    Returns:
        bytes: **Derived key in binary format.**
    """
    salt = salt or generate_salt()
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode())

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Key Management",
            message=f"{SEIGR_CELL_ID_PREFIX} Successfully derived cryptographic key using PBKDF2.",
        )

        return key
    except Exception as e:
        secure_logger.log_audit_event(
            "key_derivation_fail", "Key derivation from password failed", e
        )
        raise ValueError("Key derivation from password failed.") from e


def derive_key(
    password: str,
    salt: bytes,
    iterations: int = 100000,
    key_length: int = 32,
    use_senary: bool = True,
) -> str:
    """
    **Derives a cryptographic key and optionally encodes it to senary format.**

    Args:
        password (str): **Password for key derivation.**
        salt (bytes): **Salt value.**
        iterations (int): **Number of PBKDF2 iterations.**
        key_length (int): **Length of the derived key.**
        use_senary (bool): **Whether to encode the key in senary format.**

    Returns:
        str: **Derived key in senary or hexadecimal format.**
    """
    binary_key = derive_key_from_password(password, salt, length=key_length, iterations=iterations)
    senary_key = encode_to_senary(binary_key) if use_senary else binary_key.hex()

    secure_logger.log_audit_event(
        severity=AlertSeverity.ALERT_SEVERITY_INFO,
        category="Key Management",
        message=f"{SEIGR_CELL_ID_PREFIX} Successfully derived and encoded cryptographic key.",
    )

    return senary_key


# ===============================
# 📥 **Secure Key Storage & Retrieval**
# ===============================


def store_key(key: bytes, filename: str):
    """
    **Securely stores a cryptographic key in a file.**

    Args:
        key (bytes): **The cryptographic key to store.**
        filename (str): **Path to the file where the key will be saved.**
    """
    try:
        with open(filename, "wb") as f:
            f.write(key)

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Key Storage",
            message=f"{SEIGR_CELL_ID_PREFIX} Successfully stored cryptographic key at {filename}.",
        )

    except IOError as e:
        secure_logger.log_audit_event("key_storage_fail", f"Failed to store key to {filename}", e)
        raise


def retrieve_key(filename: str) -> bytes:
    """
    **Retrieves a stored cryptographic key from a file.**

    Args:
        filename (str): **Path to the file storing the key.**

    Returns:
        bytes: **The retrieved cryptographic key.**
    """
    try:
        with open(filename, "rb") as f:
            key = f.read()

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Key Storage",
            message=f"{SEIGR_CELL_ID_PREFIX} Successfully retrieved cryptographic key from {filename}.",
        )

        return key
    except IOError as e:
        secure_logger.log_audit_event(
            "key_retrieval_fail", f"Failed to retrieve key from {filename}", e
        )
        raise


# ===============================
# 🔑 **HMAC-Based Key Verification**
# ===============================


def generate_hmac_key(data: bytes, key: bytes, use_senary: bool = True) -> str:
    """
    **Generates an HMAC key using SHA-256.**

    Args:
        data (bytes): **Data to hash.**
        key (bytes): **Key for HMAC.**
        use_senary (bool): **Whether to encode the result in senary.**

    Returns:
        str: **HMAC key in senary or hexadecimal format.**
    """
    try:
        hmac = hashlib.pbkdf2_hmac("sha256", data, key, 1)
        hmac_key = encode_to_senary(hmac) if use_senary else hmac.hex()

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="HMAC Verification",
            message=f"{SEIGR_CELL_ID_PREFIX} Successfully generated HMAC key.",
        )

        return hmac_key
    except Exception as e:
        secure_logger.log_audit_event("hmac_generation_fail", "HMAC generation failed", e)
        raise ValueError("HMAC generation failed.") from e


def verify_hmac_key(data: bytes, expected_hmac: str, key: bytes, use_senary: bool = True) -> bool:
    """
    **Verifies an HMAC key.**

    Args:
        data (bytes): **Original data.**
        expected_hmac (str): **Expected HMAC value.**
        key (bytes): **Key for HMAC.**

    Returns:
        bool: **True if the HMAC matches, False otherwise.**
    """
    try:
        actual_hmac = generate_hmac_key(data, key, use_senary=use_senary)
        match = actual_hmac == expected_hmac

        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="HMAC Verification",
            message=f"{SEIGR_CELL_ID_PREFIX} HMAC verification {'succeeded' if match else 'failed'}.",
        )

        return match
    except Exception as e:
        secure_logger.log_audit_event("hmac_verification_fail", "HMAC verification failed", e)
        raise ValueError("HMAC verification failed.") from e
