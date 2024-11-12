# src/crypto/encoding_utils.py
import logging
from typing import Union
import cbor2

logger = logging.getLogger(__name__)

def encode_to_senary(binary_data: bytes) -> str:
    """Encodes binary data directly to a senary (base-6) encoded string."""
    senary_str = ""
    for byte in binary_data:
        # Directly convert each byte to base-6 and pad to a fixed width for consistency
        senary_str += _base6_encode(byte)
    logger.debug("Encoded data to senary format: %s", senary_str)
    return senary_str

def decode_from_senary(senary_str: str) -> bytes:
    """Decodes a senary (base-6) encoded string back to binary data."""
    binary_data = bytearray()
    for i in range(0, len(senary_str), 2):
        encoded_pair = senary_str[i:i + 2]
        try:
            byte = _base6_decode(encoded_pair)
            binary_data.append(byte)
        except ValueError as e:
            logger.error("Invalid senary encoding in '%s': %s", encoded_pair, e)
            raise ValueError(f"Invalid senary encoding: '{encoded_pair}'")
    logger.debug("Decoded senary data back to binary format.")
    return bytes(binary_data)

def _base6_encode(byte: int) -> str:
    """Converts a single byte to a senary (base-6) encoded string."""
    senary_digits = []
    for _ in range(2):  # Since we need two base-6 digits to cover a byte
        senary_digits.append(str(byte % 6))
        byte //= 6
    return ''.join(reversed(senary_digits))

def _base6_decode(senary_str: str) -> int:
    """Converts a senary (base-6) encoded string back to a byte, with error handling for invalid characters."""
    byte = 0
    for char in senary_str:
        if char not in '012345':
            raise ValueError(f"Invalid character in senary string: '{char}'")
        byte = byte * 6 + int(char)
    return byte
