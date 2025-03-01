"""
📌 **Secure Random Utilities**
Handles **cryptographic random number generation, secure token creation, salt management, and structured error logging**  
in compliance with **Seigr security protocols**.
"""

import logging
import os
import secrets

# 🔐 Seigr Imports
from src.crypto.constants import SEIGR_CELL_ID_PREFIX
from src.crypto.helpers import encode_to_senary
from src.logger.secure_logger import secure_logger
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
)
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity

logger = logging.getLogger(__name__)

# ===============================
# 🛡️ **Secure Random Data Generation**
# ===============================


def generate_secure_random_bytes(length: int = 32, use_senary: bool = False) -> bytes:
    """
    **Generates cryptographically secure random bytes.**

    Args:
        length (int): **Number of random bytes to generate.**
        use_senary (bool): **If True, encodes output in senary format.**

    Returns:
        bytes | str: **Secure random bytes, optionally senary-encoded.**
    """
    try:
        random_bytes = os.urandom(length)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Random Generation",
            message=f"{SEIGR_CELL_ID_PREFIX} Generated {length} secure random bytes.",
        )
        return encode_to_senary(random_bytes) if use_senary else random_bytes
    except Exception as e:
        _log_random_error(
            "random_bytes_generation_fail", "Failed to generate secure random bytes", e
        )
        raise ValueError("Secure random byte generation failed") from e


def generate_secure_token(length: int = 16, use_senary: bool = False) -> str:
    """
    **Generates a cryptographically secure random token.**

    Args:
        length (int): **Length of the random token in characters.**
        use_senary (bool): **If True, encodes token in senary format.**

    Returns:
        str: **Secure random token, optionally senary-encoded.**
    """
    try:
        token = secrets.token_hex(length)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Random Generation",
            message=f"{SEIGR_CELL_ID_PREFIX} Generated secure random token of length {length}.",
        )
        return encode_to_senary(token.encode()) if use_senary else token
    except Exception as e:
        _log_random_error(
            "random_token_generation_fail", "Failed to generate secure random token", e
        )
        raise ValueError("Secure random token generation failed") from e


def generate_secure_integer(max_value: int = 100000) -> int:
    """
    **Generates a cryptographically secure random integer.**

    Args:
        max_value (int): **Maximum value for the random integer.**

    Returns:
        int: **Secure random integer.**
    """
    try:
        random_int = secrets.randbelow(max_value)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Random Generation",
            message=f"{SEIGR_CELL_ID_PREFIX} Generated secure random integer below {max_value}.",
        )
        return random_int
    except Exception as e:
        _log_random_error(
            "random_integer_generation_fail", "Failed to generate secure random integer", e
        )
        raise ValueError("Secure random integer generation failed") from e


# ===============================
# 🔑 **Secure Key & Salt Generation**
# ===============================


def generate_salt(length: int = 16, use_senary: bool = False) -> bytes:
    """
    **Generates a cryptographic salt.**

    Args:
        length (int): **Length of the salt in bytes.**
        use_senary (bool): **If True, encodes salt in senary format.**

    Returns:
        bytes | str: **Secure random salt, optionally senary-encoded.**
    """
    try:
        salt = os.urandom(length)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Random Generation",
            message=f"{SEIGR_CELL_ID_PREFIX} Generated cryptographic salt of length {length}.",
        )
        return encode_to_senary(salt) if use_senary else salt
    except Exception as e:
        _log_random_error("salt_generation_fail", "Failed to generate cryptographic salt", e)
        raise ValueError("Cryptographic salt generation failed") from e


def generate_secure_key(length: int = 32, use_senary: bool = False) -> bytes:
    """
    **Generates a secure random key for cryptographic operations.**

    Args:
        length (int): **Length of the key in bytes.**
        use_senary (bool): **If True, encodes the key in senary format.**

    Returns:
        bytes | str: **Secure random key, optionally senary-encoded.**
    """
    try:
        key = os.urandom(length)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Key Management",
            message=f"{SEIGR_CELL_ID_PREFIX} Generated secure cryptographic key of length {length}.",
        )
        return encode_to_senary(key) if use_senary else key
    except Exception as e:
        _log_random_error("secure_key_generation_fail", "Failed to generate secure key", e)
        raise ValueError("Secure key generation failed") from e


# ===============================
# ⚠️ **Structured Error Logging**
# ===============================


def _log_random_error(error_id: str, message: str, exception: Exception):
    """
    **Logs an error using a structured protocol buffer entry.**

    Args:
        error_id (str): **Unique identifier for the error.**
        message (str): **Descriptive error message.**
        exception (Exception): **Exception details.**
    """
    secure_logger.log_audit_event(
        severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
        category="Random Utilities",
        message=f"{SEIGR_CELL_ID_PREFIX} {message}: {exception}",
    )
    logger.error(f"{SEIGR_CELL_ID_PREFIX} {message}: {exception}")


# ===============================
# 🧪 **Example Usage (For Testing Only)**
# ===============================

if __name__ == "__main__":
    print("🔹 Secure Random Bytes:", generate_secure_random_bytes(16))
    print("🔹 Secure Token:", generate_secure_token(8))
    print("🔹 Secure Integer:", generate_secure_integer(500))
    print("🔹 Cryptographic Salt:", generate_salt(8))
    print("🔹 Secure Key:", generate_secure_key(32))
