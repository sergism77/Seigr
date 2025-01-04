# src/crypto/helpers.py

import logging
import os
from datetime import datetime, timezone

from src.crypto.constants import SALT_SIZE, SEIGR_CELL_ID_PREFIX, SEIGR_VERSION
from src.seigr_protocol.compiled.alerting_pb2 import Alert, AlertSeverity, AlertType
from src.seigr_protocol.compiled.error_handling_pb2 import (
    ErrorLogEntry,
    ErrorResolutionStrategy,
    ErrorSeverity,
)

logger = logging.getLogger(__name__)


### 🛡️ Alert Trigger for Critical Issues ###


def _trigger_alert(message: str, severity: AlertSeverity) -> None:
    """
    Triggers an alert for critical failures in helper utilities.

    Args:
        message (str): Description of the issue.
        severity (AlertSeverity): Severity level of the alert.

    Returns:
        None
    """
    alert = Alert(
        alert_id=f"{SEIGR_CELL_ID_PREFIX}_alert_{datetime.now(timezone.utc).isoformat()}",
        message=message,
        type=AlertType.ALERT_TYPE_SYSTEM,
        severity=severity,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_component="helpers",
    )
    logger.warning(f"Alert triggered: {alert.message} with severity {severity.name}")


### 🔢 Senary Encoding/Decoding Utilities ###


def encode_to_senary(binary_data: bytes, width: int = 2) -> str:
    """
    Encodes binary data to a senary (base-6) encoded string.

    Args:
        binary_data (bytes): Data to encode.
        width (int): Fixed width for each byte segment.

    Returns:
        str: Senary-encoded string.

    Raises:
        ValueError: If encoding fails.
    """
    try:
        senary_str = "".join(_base6_encode(byte).zfill(width) for byte in binary_data)
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} Encoded to senary: {senary_str}")
        return senary_str
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_senary_encoding_error",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Senary Encoding",
            message="Failed to encode binary data to senary.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE,
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        _trigger_alert("Senary encoding failure", AlertSeverity.ALERT_SEVERITY_CRITICAL)
        raise ValueError("Senary encoding error") from e


def decode_from_senary(senary_str: str, width: int = 2) -> bytes:
    """
    Decodes a senary (base-6) encoded string back to binary data.

    Args:
        senary_str (str): Senary-encoded string.
        width (int): Fixed width for each byte segment.

    Returns:
        bytes: Decoded binary data.

    Raises:
        ValueError: If decoding fails.
    """
    try:
        binary_data = bytearray(
            _base6_decode(senary_str[i : i + width]) for i in range(0, len(senary_str), width)
        )
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} Decoded from senary: {binary_data}")
        return bytes(binary_data)
    except Exception as e:
        error_log = ErrorLogEntry(
            error_id=f"{SEIGR_CELL_ID_PREFIX}_senary_decoding_error",
            severity=ErrorSeverity.ERROR_SEVERITY_HIGH,
            component="Senary Decoding",
            message="Failed to decode senary string to binary.",
            details=str(e),
            resolution_strategy=ErrorResolutionStrategy.ERROR_STRATEGY_ALERT_AND_PAUSE,
        )
        logger.error(f"{error_log.message}: {error_log.details}")
        _trigger_alert("Senary decoding failure", AlertSeverity.ALERT_SEVERITY_CRITICAL)
        raise ValueError("Senary decoding error") from e


def is_senary(s: str) -> bool:
    """
    Checks if a string is in valid senary (base-6) format.

    Args:
        s (str): String to validate.

    Returns:
        bool: True if valid senary format, False otherwise.
    """
    return all(c in "012345" for c in s)


def _base6_encode(byte: int) -> str:
    """
    Encodes a single byte to base-6 with fixed width.

    Args:
        byte (int): Byte value to encode.

    Returns:
        str: Base-6 encoded string.
    """
    if not (0 <= byte < 256):
        raise ValueError("Byte out of range for encoding")
    senary_digits = []
    for _ in range(2):
        senary_digits.append(str(byte % 6))
        byte //= 6
    encoded_byte = "".join(reversed(senary_digits))
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Base-6 encoded byte: {encoded_byte}")
    return encoded_byte


def _base6_decode(senary_str: str) -> int:
    """
    Decodes a base-6 string back to a byte.

    Args:
        senary_str (str): Base-6 encoded string.

    Returns:
        int: Decoded byte value.
    """
    if not is_senary(senary_str):
        raise ValueError("Invalid senary string format")
    byte = sum(int(char) * (6**i) for i, char in enumerate(reversed(senary_str)))
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Base-6 decoded byte: {byte}")
    return byte


### 🧂 Salt Utility ###


def apply_salt(data: bytes, salt: str = None, salt_length: int = SALT_SIZE) -> bytes:
    """
    Applies salt to data if provided; otherwise, generates random salt.

    Args:
        data (bytes): Data to salt.
        salt (str, optional): Custom salt value.
        salt_length (int): Length of the salt in bytes.

    Returns:
        bytes: Salted data.

    Raises:
        ValueError: If salt application fails.
    """
    try:
        salt = salt.encode() if salt else os.urandom(salt_length)
        salted_data = salt + data
        logger.debug(
            f"{SEIGR_CELL_ID_PREFIX} Applied salt: {salt.hex()}, Salted data: {salted_data}"
        )
        return salted_data
    except Exception as e:
        logger.error(f"{SEIGR_CELL_ID_PREFIX} Error applying salt: {str(e)}")
        raise ValueError("Salt application error") from e


### 🏷️ Metadata Utility ###


def generate_metadata(prefix: str = "MD") -> str:
    """
    Generates a metadata string with a timestamp and prefix.

    Args:
        prefix (str): Prefix for metadata.

    Returns:
        str: Metadata string.
    """
    timestamp = datetime.now(timezone.utc).strftime("%H%M%S%f")
    metadata = f"{prefix}_{SEIGR_CELL_ID_PREFIX}_{SEIGR_VERSION}_{timestamp}"
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Generated metadata: {metadata}")
    return metadata
