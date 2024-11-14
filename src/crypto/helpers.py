# src/crypto/helpers.py

import logging
import os
from datetime import datetime, timezone
from src.crypto.constants import SEIGR_CELL_ID_PREFIX, SEIGR_VERSION, SALT_SIZE

logger = logging.getLogger(__name__)

### Base-6 (Senary) Encoding/Decoding Functions ###

def encode_to_senary(binary_data: bytes, width: int = 2) -> str:
    """
    Encodes binary data to a senary (base-6) encoded string.

    Args:
        binary_data (bytes): The binary data to encode.
        width (int): Width of each base-6 encoded element for alignment.

    Returns:
        str: Senary-encoded string.
    """
    senary_str = ""
    for byte in binary_data:
        try:
            encoded_byte = _base6_encode(byte).zfill(width)
            senary_str += encoded_byte
        except ValueError as e:
            logger.error(f"{SEIGR_CELL_ID_PREFIX}_encoding_error: Failed to encode byte to senary - {e}")
            raise
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Encoded to senary: {senary_str}")
    return senary_str

def decode_from_senary(senary_str: str, width: int = 2) -> bytes:
    """
    Decodes a senary (base-6) encoded string back to binary data.

    Args:
        senary_str (str): Senary encoded string to decode.
        width (int): Width of each base-6 encoded element to decode.

    Returns:
        bytes: Original binary data.
    """
    binary_data = bytearray()
    for i in range(0, len(senary_str), width):
        encoded_segment = senary_str[i:i + width]
        try:
            binary_data.append(_base6_decode(encoded_segment))
        except ValueError as e:
            logger.error(f"{SEIGR_CELL_ID_PREFIX}_decoding_error: Failed to decode senary segment - {e}")
            raise
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Decoded from senary: {binary_data}")
    return bytes(binary_data)

def _base6_encode(byte: int) -> str:
    """Encodes a single byte to base-6 with fixed width."""
    if not (0 <= byte < 256):
        raise ValueError("Byte out of range for encoding")
    senary_digits = []
    for _ in range(2):
        senary_digits.append(str(byte % 6))
        byte //= 6
    encoded_byte = ''.join(reversed(senary_digits))
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Base-6 encoded byte: {encoded_byte}")
    return encoded_byte

def _base6_decode(senary_str: str) -> int:
    """Decodes a base-6 string back to a byte."""
    byte = 0
    for char in senary_str:
        if char not in "012345":
            raise ValueError("Invalid character in senary string")
        byte = byte * 6 + int(char)
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Base-6 decoded byte: {byte}")
    return byte

### Salt Utility ###

def apply_salt(data: bytes, salt: str = None, salt_length: int = SALT_SIZE) -> bytes:
    """
    Applies salt to the data if provided, generating it if not supplied.

    Args:
        data (bytes): Original data to salt.
        salt (str): Optional string salt to apply.
        salt_length (int): Length of randomly generated salt if no salt is provided.

    Returns:
        bytes: Salted data.
    """
    try:
        salt = salt.encode() if salt else os.urandom(salt_length)
        salted_data = salt + data
        logger.debug(f"{SEIGR_CELL_ID_PREFIX} Applied salt: {salt.hex()}, Salted data: {salted_data}")
        return salted_data
    except Exception as e:
        logger.error(f"{SEIGR_CELL_ID_PREFIX}_salt_application_error: Error applying salt - {e}")
        raise ValueError("Salt application error") from e

### Metadata and Logging Utility ###

def generate_metadata(prefix: str = "MD") -> str:
    """
    Generates a metadata string with a timestamp and prefix for traceability.

    Args:
        prefix (str): Prefix for metadata context.

    Returns:
        str: Generated metadata string.
    """
    timestamp = datetime.now(timezone.utc).strftime("%H%M%S%f")
    metadata = f"{prefix}_{SEIGR_CELL_ID_PREFIX}_{SEIGR_VERSION}_{timestamp}"
    logger.debug(f"{SEIGR_CELL_ID_PREFIX} Generated metadata: {metadata}")
    return metadata
