"""
📌 **Seigr Helper Utilities**
Provides **secure encoding, salt application, and metadata generation** while ensuring **Seigr protocol compliance**.
Includes **structured logging, error handling, and alert triggering** for maximum resilience.
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Optional

# 🔐 Seigr Imports
from src.crypto.constants import SALT_SIZE, SEIGR_CELL_ID_PREFIX, SEIGR_VERSION
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity, AlertType
from src.seigr_protocol.compiled.alerting_pb2 import AlertSeverity  # ✅ Correct import
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
)  # ✅ Keep only necessary imports
from src.logger.secure_logger import secure_logger
from src.crypto.alert_utils import trigger_alert  # ✅ Use centralized alerting
from google.protobuf.timestamp_pb2 import Timestamp

# ===============================
# ⏳ **Timestamp Utility**
# ===============================


def get_protobuf_timestamp() -> Timestamp:
    """
    **Returns the current UTC time as a Protobuf Timestamp.**

    Returns:
        Timestamp: **Protobuf timestamp object**
    """
    now = datetime.now(timezone.utc)
    timestamp = Timestamp()
    timestamp.FromDatetime(now)  # ✅ Ensures proper Protobuf conversion
    return timestamp


def get_datetime_now() -> datetime:
    """
    **Returns the current UTC time as a `datetime` object.**

    Returns:
        datetime: **Current UTC datetime.**
    """
    return datetime.now(timezone.utc)


# ===============================
# 🔢 **Senary Encoding/Decoding Utilities**
# ===============================


def encode_to_senary(binary_data: bytes, width: int = 2) -> str:
    """
    **Encodes binary data to a senary (base-6) encoded string.**

    Args:
        binary_data (bytes): **Data to encode.**
        width (int): **Fixed width for each byte segment.**

    Returns:
        str: **Senary-encoded string.**

    Raises:
        ValueError: **If encoding fails.**
    """
    try:
        senary_str = "".join(_base6_encode(byte).zfill(width) for byte in binary_data)
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Encoding",
            message="✅ Senary encoding successful.",
            timestamp=get_datetime_now(),
        )
        return senary_str
    except Exception as e:
        trigger_alert(
            message="Senary encoding failure",
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            alert_type=AlertType.ALERT_TYPE_SYSTEM,
            source_component="helpers",
        )
        raise ValueError("Senary encoding error") from e


def decode_from_senary(senary_str: str, width: int = 2) -> bytes:
    """
    **Decodes a senary (base-6) encoded string back to binary data.**

    Args:
        senary_str (str): **Senary-encoded string.**
        width (int): **Fixed width for each byte segment.**

    Returns:
        bytes: **Decoded binary data.**

    Raises:
        ValueError: **If decoding fails.**
    """
    # ✅ FIX: Enforce length validation
    if len(senary_str) % width != 0:
        raise ValueError("Invalid senary length")

    try:
        binary_data = bytearray(
            _base6_decode(senary_str[i : i + width]) for i in range(0, len(senary_str), width)
        )
        secure_logger.log_audit_event(
            severity=AlertSeverity.ALERT_SEVERITY_INFO,
            category="Decoding",
            message="✅ Senary decoding successful.",
            timestamp=get_datetime_now(),
        )
        return bytes(binary_data)
    except Exception:
        raise ValueError("Senary decoding error")  # ✅ FIX: Standardize error message


def is_senary(s: str) -> bool:
    """
    **Checks if a string is in valid senary (base-6) format.**

    Args:
        s (str): **String to validate.**

    Returns:
        bool: **True if valid senary format, False otherwise.**
    """
    return all(c in "012345" for c in s)


def _base6_encode(byte: int) -> str:
    """
    **Encodes a single byte to base-6 with fixed width.**

    Args:
        byte (int): **Byte value to encode.**

    Returns:
        str: **Base-6 encoded string.**
    """
    if not (0 <= byte < 256):
        raise ValueError("Byte out of range for encoding")
    senary_digits = []
    for _ in range(2):
        senary_digits.append(str(byte % 6))
        byte //= 6
    return "".join(reversed(senary_digits))


def _base6_decode(senary_str: str) -> int:
    """
    **Decodes a base-6 string back to a byte.**

    Args:
        senary_str (str): **Base-6 encoded string.**

    Returns:
        int: **Decoded byte value.**
    """
    if not is_senary(senary_str):
        raise ValueError("Invalid senary string format")
    return sum(int(char) * (6**i) for i, char in enumerate(reversed(senary_str)))


# ===============================
# 🧂 **Salt Utility**
# ===============================


def apply_salt(data: bytes, salt: Optional[str] = None, salt_length: int = SALT_SIZE) -> bytes:
    """
    **Applies salt to data if provided; otherwise, generates random salt.**

    Args:
        data (bytes): **Data to salt.**
        salt (str, optional): **Custom salt value.**
        salt_length (int): **Length of the salt in bytes.**

    Returns:
        bytes: **Salted data.**

    Raises:
        ValueError: **If salt application fails.**
    """
    try:
        salt = salt.encode() if salt else os.urandom(salt_length)
        return salt + data
    except Exception as e:
        trigger_alert(
            message="Salt application error",
            severity=AlertSeverity.ALERT_SEVERITY_CRITICAL,
            alert_type=AlertType.ALERT_TYPE_SYSTEM,
            source_component="helpers",
        )
        raise ValueError("Salt application error") from e


# ===============================
# 🏷️ **Metadata Utility**
# ===============================


def generate_metadata(prefix: str = "MD") -> str:
    """
    **Generates a metadata string with a timestamp and prefix.**

    Args:
        prefix (str): **Prefix for metadata.**

    Returns:
        str: **Metadata string.**
    """
    timestamp = get_datetime_now()
    timestamp_str = timestamp.strftime("%H%M%S%f")
    metadata = f"{prefix}_{SEIGR_CELL_ID_PREFIX}_{SEIGR_VERSION}_{timestamp_str}"
    secure_logger.log_audit_event(
        severity=AlertSeverity.ALERT_SEVERITY_INFO,
        category="Metadata",
        message="✅ Metadata successfully generated.",
        timestamp=timestamp,
        log_data={"metadata": metadata},
    )
    return metadata
