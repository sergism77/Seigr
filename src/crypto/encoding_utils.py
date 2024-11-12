# src/crypto/encoding_utils.py

import logging
from typing import Union
import cbor2

logger = logging.getLogger(__name__)

def encode_to_senary(binary_data: bytes) -> str:
    """Encodes binary data to a senary-encoded string with reversible transformations."""
    senary_str = ""
    previous_value = 1  # Seed for transformations

    for i, byte in enumerate(binary_data):
        transformed_byte = _substitution_permutation(byte + previous_value, i)
        previous_value = transformed_byte
        base6_encoded = _base6_encode(transformed_byte).zfill(2)  # Ensure 2 characters per byte
        senary_str += base6_encoded
        logger.debug(f"Encoded byte {i}: original {byte}, transformed {transformed_byte}, senary {base6_encoded}")

    logger.debug("Successfully encoded data to senary format.")
    return senary_str

def decode_from_senary(senary_str: str) -> bytes:
    """Decodes a senary (base-6) encoded string back to binary data."""
    if len(senary_str) % 2 != 0:
        raise ValueError("Senary string length must be even for consistent byte encoding.")

    binary_data = bytearray()
    previous_value = 1

    for i in range(0, len(senary_str), 2):
        encoded_pair = senary_str[i:i + 2]
        try:
            byte = _base6_decode(encoded_pair)
            reversed_byte = _reverse_substitution_permutation(byte, previous_value, i // 2)
            binary_data.append(reversed_byte)
            previous_value = byte
            logger.debug(f"Decoded pair {encoded_pair}: senary {byte}, original {reversed_byte}")
        except ValueError as e:
            logger.error(f"Invalid senary encoding in '{encoded_pair}' at index {i}: {e}")
            raise ValueError(f"Invalid senary encoding: '{encoded_pair}'") from e

    logger.debug("Successfully decoded senary data back to binary format.")
    return bytes(binary_data)

### Helper functions for encoding and decoding transformations ###

def _substitution_permutation(value: int, position: int) -> int:
    """Applies substitution and bit rotation to a byte, based on its position."""
    substituted = (value ^ (position * 17 + 23)) & 0xFF
    rotated = ((substituted << 3) & 0xFF) | (substituted >> 5)
    logger.debug(f"Substitution-permutation: input {value}, substituted {substituted}, rotated {rotated}")
    return rotated

def _reverse_substitution_permutation(value: int, prev_val: int, position: int) -> int:
    """Reverses the substitution and rotation applied in _substitution_permutation."""
    rotated = ((value >> 3) & 0x1F) | ((value & 0x1F) << 5)
    substituted = (rotated ^ (position * 17 + 23)) & 0xFF
    reversed_val = (substituted - prev_val) & 0xFF
    logger.debug(f"Reversed permutation: input {value}, rotated {rotated}, substituted {substituted}, result {reversed_val}")
    return reversed_val

def _base6_encode(byte: int) -> str:
    """Converts a single byte to a senary (base-6) encoded string with fixed width."""
    senary_digits = []
    for _ in range(2):  # Two base-6 digits for byte coverage
        senary_digits.append(str(byte % 6))
        byte //= 6
    return ''.join(reversed(senary_digits))

def _base6_decode(senary_str: str) -> int:
    """Converts a senary (base-6) encoded string back to a byte, with error handling for invalid characters."""
    byte = 0
    for char in senary_str:
        if char not in '012345':
            logger.error(f"Invalid character in senary string: '{char}'")
            raise ValueError(f"Invalid character in senary string: '{char}'")
        byte = byte * 6 + int(char)
    return byte
